"""
Performance optimization utilities for ReconForge
"""

import asyncio
import time
import psutil
import resource
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import functools
import weakref
import threading
from pathlib import Path

from utils.logging import main_logger


@dataclass
class PerformanceMetrics:
    """Performance metrics tracking"""
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    disk_io_read_mb: float
    disk_io_write_mb: float
    network_sent_mb: float
    network_recv_mb: float
    active_threads: int
    active_processes: int
    scan_queue_size: int
    timestamp: datetime


class ResourceMonitor:
    """System resource monitoring and management"""
    
    def __init__(self, max_cpu_percent: float = 80.0, max_memory_percent: float = 85.0):
        self.max_cpu_percent = max_cpu_percent
        self.max_memory_percent = max_memory_percent
        self.metrics_history: List[PerformanceMetrics] = []
        self.monitoring = False
        self._monitor_task = None
        self._start_time = time.time()
        
        # Initial system metrics
        self._initial_io = psutil.disk_io_counters()
        self._initial_network = psutil.net_io_counters()
    
    async def start_monitoring(self, interval: int = 30):
        """Start continuous resource monitoring"""
        if self.monitoring:
            return
        
        self.monitoring = True
        self._monitor_task = asyncio.create_task(self._monitor_loop(interval))
        main_logger.info(f"Started resource monitoring (interval: {interval}s)")
    
    async def stop_monitoring(self):
        """Stop resource monitoring"""
        if not self.monitoring:
            return
        
        self.monitoring = False
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        
        main_logger.info("Stopped resource monitoring")
    
    async def _monitor_loop(self, interval: int):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                metrics = self.get_current_metrics()
                self.metrics_history.append(metrics)
                
                # Keep only last 1000 metrics (about 8 hours at 30s intervals)
                if len(self.metrics_history) > 1000:
                    self.metrics_history = self.metrics_history[-1000:]
                
                # Check resource thresholds
                await self._check_resource_thresholds(metrics)
                
                await asyncio.sleep(interval)
                
            except Exception as e:
                main_logger.error(f"Error in resource monitoring: {e}")
                await asyncio.sleep(interval)
    
    def get_current_metrics(self) -> PerformanceMetrics:
        """Get current system performance metrics"""
        try:
            # CPU and Memory
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            
            # Disk I/O
            current_io = psutil.disk_io_counters()
            if current_io and self._initial_io:
                disk_read_mb = (current_io.read_bytes - self._initial_io.read_bytes) / (1024 * 1024)
                disk_write_mb = (current_io.write_bytes - self._initial_io.write_bytes) / (1024 * 1024)
            else:
                disk_read_mb = disk_write_mb = 0.0
            
            # Network I/O
            current_network = psutil.net_io_counters()
            if current_network and self._initial_network:
                network_sent_mb = (current_network.bytes_sent - self._initial_network.bytes_sent) / (1024 * 1024)
                network_recv_mb = (current_network.bytes_recv - self._initial_network.bytes_recv) / (1024 * 1024)
            else:
                network_sent_mb = network_recv_mb = 0.0
            
            # Process information
            current_process = psutil.Process()
            active_threads = current_process.num_threads()
            
            # Count child processes
            try:
                children = current_process.children(recursive=True)
                active_processes = len(children)
            except psutil.NoSuchProcess:
                active_processes = 0
            
            return PerformanceMetrics(
                cpu_percent=cpu_percent,
                memory_percent=memory.percent,
                memory_used_mb=memory.used / (1024 * 1024),
                disk_io_read_mb=disk_read_mb,
                disk_io_write_mb=disk_write_mb,
                network_sent_mb=network_sent_mb,
                network_recv_mb=network_recv_mb,
                active_threads=active_threads,
                active_processes=active_processes,
                scan_queue_size=0,  # Will be updated by scan manager
                timestamp=datetime.now()
            )
            
        except Exception as e:
            main_logger.error(f"Failed to get performance metrics: {e}")
            return PerformanceMetrics(
                cpu_percent=0.0, memory_percent=0.0, memory_used_mb=0.0,
                disk_io_read_mb=0.0, disk_io_write_mb=0.0,
                network_sent_mb=0.0, network_recv_mb=0.0,
                active_threads=0, active_processes=0, scan_queue_size=0,
                timestamp=datetime.now()
            )
    
    async def _check_resource_thresholds(self, metrics: PerformanceMetrics):
        """Check if resource usage exceeds thresholds"""
        warnings = []
        
        if metrics.cpu_percent > self.max_cpu_percent:
            warnings.append(f"High CPU usage: {metrics.cpu_percent:.1f}%")
        
        if metrics.memory_percent > self.max_memory_percent:
            warnings.append(f"High memory usage: {metrics.memory_percent:.1f}%")
        
        if metrics.active_threads > 200:
            warnings.append(f"High thread count: {metrics.active_threads}")
        
        if warnings:
            main_logger.warning(f"Resource threshold exceeded: {'; '.join(warnings)}")
    
    def get_resource_summary(self) -> Dict[str, Any]:
        """Get resource usage summary"""
        if not self.metrics_history:
            return {"status": "No metrics available"}
        
        recent_metrics = self.metrics_history[-10:]  # Last 10 measurements
        
        avg_cpu = sum(m.cpu_percent for m in recent_metrics) / len(recent_metrics)
        avg_memory = sum(m.memory_percent for m in recent_metrics) / len(recent_metrics)
        max_threads = max(m.active_threads for m in recent_metrics)
        
        uptime_seconds = time.time() - self._start_time
        uptime_str = str(timedelta(seconds=int(uptime_seconds)))
        
        return {
            "status": "healthy",
            "uptime": uptime_str,
            "avg_cpu_percent": round(avg_cpu, 1),
            "avg_memory_percent": round(avg_memory, 1),
            "max_threads": max_threads,
            "total_metrics": len(self.metrics_history),
            "monitoring_active": self.monitoring
        }


class CacheManager:
    """Intelligent caching system with TTL and size limits"""
    
    def __init__(self, max_size: int = 10000, default_ttl: int = 3600):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._access_times: Dict[str, float] = {}
        self._lock = threading.RLock()
    
    def get(self, key: str, default=None) -> Any:
        """Get item from cache"""
        with self._lock:
            if key not in self._cache:
                return default
            
            entry = self._cache[key]
            
            # Check TTL
            if time.time() > entry['expires']:
                del self._cache[key]
                if key in self._access_times:
                    del self._access_times[key]
                return default
            
            # Update access time
            self._access_times[key] = time.time()
            return entry['value']
    
    def set(self, key: str, value: Any, ttl: int = None) -> None:
        """Set item in cache"""
        with self._lock:
            if ttl is None:
                ttl = self.default_ttl
            
            # Ensure cache size limit
            while len(self._cache) >= self.max_size:
                self._evict_oldest()
            
            self._cache[key] = {
                'value': value,
                'expires': time.time() + ttl,
                'created': time.time()
            }
            self._access_times[key] = time.time()
    
    def delete(self, key: str) -> bool:
        """Delete item from cache"""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                if key in self._access_times:
                    del self._access_times[key]
                return True
            return False
    
    def clear(self) -> None:
        """Clear all cache entries"""
        with self._lock:
            self._cache.clear()
            self._access_times.clear()
    
    def _evict_oldest(self) -> None:
        """Evict oldest accessed item"""
        if not self._access_times:
            return
        
        oldest_key = min(self._access_times, key=self._access_times.get)
        if oldest_key in self._cache:
            del self._cache[oldest_key]
        del self._access_times[oldest_key]
    
    def cleanup_expired(self) -> int:
        """Remove expired entries and return count"""
        with self._lock:
            current_time = time.time()
            expired_keys = []
            
            for key, entry in self._cache.items():
                if current_time > entry['expires']:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self._cache[key]
                if key in self._access_times:
                    del self._access_times[key]
            
            return len(expired_keys)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._lock:
            return {
                'total_entries': len(self._cache),
                'max_size': self.max_size,
                'hit_rate': 0.0,  # Would need hit/miss tracking
                'memory_usage_mb': self._estimate_memory_usage()
            }
    
    def _estimate_memory_usage(self) -> float:
        """Estimate cache memory usage in MB"""
        import sys
        
        total_size = 0
        for key, entry in self._cache.items():
            total_size += sys.getsizeof(key)
            total_size += sys.getsizeof(entry['value'])
            total_size += sys.getsizeof(entry)
        
        return total_size / (1024 * 1024)


class AsyncRateLimiter:
    """Asynchronous rate limiter with different strategies"""
    
    def __init__(self, rate: int, period: int = 60, strategy: str = "sliding_window"):
        self.rate = rate
        self.period = period
        self.strategy = strategy
        self._requests: List[float] = []
        self._lock = asyncio.Lock()
        
        # Token bucket strategy
        self._tokens = rate
        self._last_refill = time.time()
    
    async def acquire(self, tokens: int = 1) -> bool:
        """Acquire permission to proceed"""
        async with self._lock:
            if self.strategy == "sliding_window":
                return await self._sliding_window_acquire(tokens)
            elif self.strategy == "token_bucket":
                return await self._token_bucket_acquire(tokens)
            else:
                return True
    
    async def _sliding_window_acquire(self, tokens: int) -> bool:
        """Sliding window rate limiting"""
        current_time = time.time()
        cutoff_time = current_time - self.period
        
        # Remove old requests
        self._requests = [req_time for req_time in self._requests if req_time > cutoff_time]
        
        # Check if we can proceed
        if len(self._requests) + tokens <= self.rate:
            for _ in range(tokens):
                self._requests.append(current_time)
            return True
        
        return False
    
    async def _token_bucket_acquire(self, tokens: int) -> bool:
        """Token bucket rate limiting"""
        current_time = time.time()
        elapsed = current_time - self._last_refill
        
        # Refill tokens
        tokens_to_add = int(elapsed * (self.rate / self.period))
        self._tokens = min(self.rate, self._tokens + tokens_to_add)
        self._last_refill = current_time
        
        # Check if we have enough tokens
        if self._tokens >= tokens:
            self._tokens -= tokens
            return True
        
        return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiter statistics"""
        return {
            'strategy': self.strategy,
            'rate': self.rate,
            'period': self.period,
            'current_requests': len(self._requests) if self.strategy == "sliding_window" else None,
            'available_tokens': self._tokens if self.strategy == "token_bucket" else None
        }


class ConcurrencyManager:
    """Manage concurrent operations with resource awareness"""
    
    def __init__(self, max_concurrent: int = 50, max_cpu_percent: float = 80.0):
        self.max_concurrent = max_concurrent
        self.max_cpu_percent = max_cpu_percent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._active_tasks = 0
        self._completed_tasks = 0
        self._failed_tasks = 0
        self._lock = asyncio.Lock()
        
        # Thread and process pools for CPU-intensive tasks
        self._thread_pool = ThreadPoolExecutor(max_workers=min(32, (psutil.cpu_count() or 1) + 4))
        self._process_pool = ProcessPoolExecutor(max_workers=min(8, psutil.cpu_count() or 1))
    
    async def run_task(self, coro_or_func, *args, use_thread_pool: bool = False, 
                      use_process_pool: bool = False, **kwargs):
        """Run task with concurrency control"""
        async with self._semaphore:
            async with self._lock:
                self._active_tasks += 1
            
            try:
                # Check system resources
                cpu_percent = psutil.cpu_percent(interval=0.1)
                if cpu_percent > self.max_cpu_percent:
                    main_logger.warning(f"High CPU usage ({cpu_percent:.1f}%), throttling tasks")
                    await asyncio.sleep(1)
                
                # Execute task based on type
                if use_process_pool:
                    # For CPU-intensive tasks
                    loop = asyncio.get_event_loop()
                    result = await loop.run_in_executor(self._process_pool, coro_or_func, *args, **kwargs)
                elif use_thread_pool:
                    # For I/O-bound blocking tasks
                    loop = asyncio.get_event_loop()
                    result = await loop.run_in_executor(self._thread_pool, coro_or_func, *args, **kwargs)
                else:
                    # For async coroutines
                    if asyncio.iscoroutinefunction(coro_or_func):
                        result = await coro_or_func(*args, **kwargs)
                    else:
                        result = coro_or_func(*args, **kwargs)
                
                async with self._lock:
                    self._completed_tasks += 1
                
                return result
                
            except Exception as e:
                async with self._lock:
                    self._failed_tasks += 1
                raise e
            finally:
                async with self._lock:
                    self._active_tasks -= 1
    
    async def wait_for_capacity(self, required_slots: int = 1) -> None:
        """Wait until sufficient capacity is available"""
        while self._active_tasks + required_slots > self.max_concurrent:
            await asyncio.sleep(0.1)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get concurrency statistics"""
        return {
            'max_concurrent': self.max_concurrent,
            'active_tasks': self._active_tasks,
            'completed_tasks': self._completed_tasks,
            'failed_tasks': self._failed_tasks,
            'success_rate': self._completed_tasks / (self._completed_tasks + self._failed_tasks) if (self._completed_tasks + self._failed_tasks) > 0 else 1.0,
            'thread_pool_size': self._thread_pool._max_workers,
            'process_pool_size': self._process_pool._max_workers
        }
    
    async def shutdown(self):
        """Shutdown executor pools"""
        self._thread_pool.shutdown(wait=True)
        self._process_pool.shutdown(wait=True)


def memoize_with_ttl(ttl_seconds: int = 3600):
    """Decorator for memoizing function results with TTL"""
    def decorator(func):
        cache = {}
        
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            # Create cache key
            key = str(args) + str(sorted(kwargs.items()))
            current_time = time.time()
            
            # Check cache
            if key in cache:
                result, timestamp = cache[key]
                if current_time - timestamp < ttl_seconds:
                    return result
                else:
                    del cache[key]
            
            # Execute function and cache result
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)
            
            cache[key] = (result, current_time)
            
            # Cleanup old cache entries (simple approach)
            if len(cache) > 1000:
                cutoff_time = current_time - ttl_seconds
                expired_keys = [k for k, (_, ts) in cache.items() if ts < cutoff_time]
                for k in expired_keys:
                    del cache[k]
            
            return result
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            # Create cache key
            key = str(args) + str(sorted(kwargs.items()))
            current_time = time.time()
            
            # Check cache
            if key in cache:
                result, timestamp = cache[key]
                if current_time - timestamp < ttl_seconds:
                    return result
                else:
                    del cache[key]
            
            # Execute function and cache result
            result = func(*args, **kwargs)
            cache[key] = (result, current_time)
            
            return result
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    
    return decorator


class PerformanceProfiler:
    """Profile function execution times and resource usage"""
    
    def __init__(self):
        self.profiles: Dict[str, List[Dict[str, Any]]] = {}
        self._lock = threading.Lock()
    
    def profile_function(self, name: str = None):
        """Decorator to profile function execution"""
        def decorator(func):
            func_name = name or f"{func.__module__}.{func.__name__}"
            
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                start_time = time.time()
                start_memory = psutil.Process().memory_info().rss / (1024 * 1024)
                
                try:
                    if asyncio.iscoroutinefunction(func):
                        result = await func(*args, **kwargs)
                    else:
                        result = func(*args, **kwargs)
                    
                    success = True
                    error = None
                except Exception as e:
                    result = None
                    success = False
                    error = str(e)
                    raise
                finally:
                    end_time = time.time()
                    end_memory = psutil.Process().memory_info().rss / (1024 * 1024)
                    
                    profile_data = {
                        'timestamp': datetime.now().isoformat(),
                        'duration_seconds': end_time - start_time,
                        'memory_delta_mb': end_memory - start_memory,
                        'success': success,
                        'error': error,
                        'args_count': len(args),
                        'kwargs_count': len(kwargs)
                    }
                    
                    with self._lock:
                        if func_name not in self.profiles:
                            self.profiles[func_name] = []
                        self.profiles[func_name].append(profile_data)
                        
                        # Keep only last 100 profiles per function
                        if len(self.profiles[func_name]) > 100:
                            self.profiles[func_name] = self.profiles[func_name][-100:]
                
                return result
            
            return async_wrapper
        
        return decorator
    
    def get_function_stats(self, function_name: str) -> Dict[str, Any]:
        """Get statistics for a specific function"""
        with self._lock:
            if function_name not in self.profiles:
                return {"error": "Function not found"}
            
            profiles = self.profiles[function_name]
            durations = [p['duration_seconds'] for p in profiles]
            memory_deltas = [p['memory_delta_mb'] for p in profiles]
            success_count = sum(1 for p in profiles if p['success'])
            
            return {
                'total_calls': len(profiles),
                'success_rate': success_count / len(profiles) if profiles else 0,
                'avg_duration': sum(durations) / len(durations) if durations else 0,
                'max_duration': max(durations) if durations else 0,
                'min_duration': min(durations) if durations else 0,
                'avg_memory_delta': sum(memory_deltas) / len(memory_deltas) if memory_deltas else 0,
                'max_memory_delta': max(memory_deltas) if memory_deltas else 0
            }
    
    def get_all_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all profiled functions"""
        with self._lock:
            return {func_name: self.get_function_stats(func_name) 
                   for func_name in self.profiles.keys()}


# Global instances
resource_monitor = ResourceMonitor()
cache_manager = CacheManager()
concurrency_manager = ConcurrencyManager()
performance_profiler = PerformanceProfiler()


async def optimize_system_resources():
    """Optimize system resources and cleanup"""
    try:
        # Clear expired cache entries
        expired_count = cache_manager.cleanup_expired()
        if expired_count > 0:
            main_logger.info(f"Cleaned up {expired_count} expired cache entries")
        
        # Force garbage collection
        import gc
        collected = gc.collect()
        if collected > 0:
            main_logger.info(f"Garbage collected {collected} objects")
        
        # Clear DNS cache if too many entries
        # This would be implementation-specific
        
        # Log current resource usage
        metrics = resource_monitor.get_current_metrics()
        main_logger.info(f"System resources - CPU: {metrics.cpu_percent:.1f}%, "
                        f"Memory: {metrics.memory_percent:.1f}%, "
                        f"Threads: {metrics.active_threads}")
        
        return True
        
    except Exception as e:
        main_logger.error(f"Failed to optimize system resources: {e}")
        return False


def get_performance_summary() -> Dict[str, Any]:
    """Get comprehensive performance summary"""
    return {
        'resource_monitor': resource_monitor.get_resource_summary(),
        'cache_manager': cache_manager.get_stats(),
        'concurrency_manager': concurrency_manager.get_stats(),
        'performance_profiles': performance_profiler.get_all_stats()
    }