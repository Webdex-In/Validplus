from functools import wraps
from cachetools import TTLCache
from typing import Dict, Any, Optional, List, Union
import dns.resolver
import dns.exception
import time
import logging
from threading import Lock
from config import DNS_CONFIG

class DNSCache:
    """DNS caching utility with enhanced error handling and monitoring"""

    def __init__(self, ttl: int = DNS_CONFIG['CACHE_TTL'], 
                 maxsize: int = DNS_CONFIG['CACHE_MAXSIZE']):
        """
        Initialize DNS cache

        Args:
            ttl: Time to live for cache entries in seconds
            maxsize: Maximum number of entries in cache
        """
        self._cache = TTLCache(maxsize=maxsize, ttl=ttl)
        self._lock = Lock()
        self.resolver = dns.resolver.Resolver()

        # Configure resolver from settings
        self.resolver.nameservers = DNS_CONFIG['NAMESERVERS']
        self.resolver.timeout = DNS_CONFIG['TIMEOUT']
        self.resolver.lifetime = DNS_CONFIG['LIFETIME']

        # Initialize logging
        self.logger = logging.getLogger('dns_cache')

        # Statistics
        self._stats = {
            'hits': 0,
            'misses': 0,
            'errors': 0,
            'last_error': None,
            'last_error_time': None
        }

    def _cache_key(self, domain: str, record_type: str) -> str:
        """
        Generate cache key from domain and record type

        Args:
            domain: Domain name
            record_type: DNS record type

        Returns:
            str: Cache key
        """
        return f"{domain.lower()}:{record_type.upper()}"

    def lookup(self, domain: str, record_type: str = 'MX') -> Optional[Dict[str, Any]]:
        """
        Perform a cached DNS lookup with retry logic

        Args:
            domain: Domain name to lookup
            record_type: DNS record type

        Returns:
            Dict containing lookup results or None if lookup fails
        """
        cache_key = self._cache_key(domain, record_type)

        # Try to get from cache first
        with self._lock:
            if cache_key in self._cache:
                self._stats['hits'] += 1
                return self._cache[cache_key]
            self._stats['misses'] += 1

        # Not in cache, perform lookup with retries
        for attempt in range(DNS_CONFIG['RETRY_COUNT']):
            try:
                start_time = time.time()
                records = self.resolver.resolve(domain, record_type)
                lookup_time = time.time() - start_time

                # Format results based on record type
                if record_type == 'MX':
                    result = {
                        'records': [
                            {
                                'exchange': str(r.exchange).rstrip('.'),
                                'preference': r.preference
                            } for r in records
                        ],
                        'lookup_time': lookup_time,
                        'timestamp': time.time()
                    }
                elif record_type == 'TXT':
                    result = {
                        'records': [r.strings[0].decode() for r in records],
                        'lookup_time': lookup_time,
                        'timestamp': time.time()
                    }
                else:
                    result = {
                        'records': [str(r) for r in records],
                        'lookup_time': lookup_time,
                        'timestamp': time.time()
                    }

                # Cache the successful result
                with self._lock:
                    self._cache[cache_key] = result
                return result

            except dns.resolver.NXDOMAIN:
                self._update_error_stats('NXDOMAIN', domain)
                result = {
                    'error': 'NXDOMAIN',
                    'lookup_time': time.time() - start_time
                }
                with self._lock:
                    self._cache[cache_key] = result
                return result

            except dns.resolver.NoAnswer:
                self._update_error_stats('NoAnswer', domain)
                result = {
                    'error': 'NoAnswer',
                    'lookup_time': time.time() - start_time
                }
                with self._lock:
                    self._cache[cache_key] = result
                return result

            except dns.resolver.Timeout:
                self._update_error_stats('Timeout', domain)
                if attempt < DNS_CONFIG['RETRY_COUNT'] - 1:
                    time.sleep(DNS_CONFIG['RETRY_TIMEOUT'])
                    continue
                result = {
                    'error': 'Timeout',
                    'lookup_time': time.time() - start_time
                }
                return result

            except Exception as e:
                self._update_error_stats(str(e), domain)
                if attempt < DNS_CONFIG['RETRY_COUNT'] - 1:
                    time.sleep(DNS_CONFIG['RETRY_TIMEOUT'])
                    continue
                result = {
                    'error': str(e),
                    'lookup_time': time.time() - start_time
                }
                return result

        return None

    def _update_error_stats(self, error: str, domain: str) -> None:
        """Update error statistics"""
        with self._lock:
            self._stats['errors'] += 1
            self._stats['last_error'] = f"{error} ({domain})"
            self._stats['last_error_time'] = time.time()
        self.logger.error(f"DNS lookup error for {domain}: {error}")

    def clear(self) -> None:
        """Clear the cache"""
        with self._lock:
            self._cache.clear()
            self.logger.info("DNS cache cleared")

    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics and health metrics
        
        Returns:
            Dict containing cache statistics and health information
        """
        with self._lock:
            stats = {
                # Cache stats
                'size': len(self._cache),
                'maxsize': self._cache.maxsize,
                'ttl': self._cache.ttl,
                'currsize': len(self._cache),
                
                # Hit/miss stats
                'hits': self._stats['hits'],
                'misses': self._stats['misses'],
                'hit_ratio': (self._stats['hits'] / (self._stats['hits'] + self._stats['misses']) 
                             if (self._stats['hits'] + self._stats['misses']) > 0 else 0),
                
                # Error stats
                'errors': self._stats['errors'],
                'last_error': self._stats['last_error'],
                'last_error_time': self._stats['last_error_time'],
                
                # Health metrics
                'nameservers': self.resolver.nameservers,
                'timeout': self.resolver.timeout,
                'lifetime': self.resolver.lifetime
            }
            return stats

    def bulk_lookup(self, domains: List[str], record_type: str = 'MX') -> Dict[str, Any]:
        """
        Perform bulk DNS lookups efficiently
        
        Args:
            domains: List of domain names to lookup
            record_type: DNS record type
            
        Returns:
            Dict containing results for each domain
        """
        results = {}
        for domain in domains:
            results[domain] = self.lookup(domain, record_type)
        return results

    def prefetch(self, domain: str, record_types: List[str] = ['MX', 'TXT', 'A']) -> None:
        """
        Prefetch DNS records for a domain
        
        Args:
            domain: Domain name to prefetch
            record_types: List of record types to prefetch
        """
        for record_type in record_types:
            self.lookup(domain, record_type)

    def is_valid_domain(self, domain: str) -> bool:
        """
        Check if a domain exists and has valid DNS records
        
        Args:
            domain: Domain name to check
            
        Returns:
            bool: Whether domain is valid
        """
        result = self.lookup(domain, 'A')
        if not result or 'error' in result:
            return False
        return True

    def get_mx_servers(self, domain: str) -> List[Dict[str, Union[str, int]]]:
        """
        Get sorted list of MX servers for a domain
        
        Args:
            domain: Domain name to lookup
            
        Returns:
            List of dicts containing MX server information
        """
        result = self.lookup(domain, 'MX')
        if not result or 'error' in result:
            return []
            
        mx_records = result.get('records', [])
        return sorted(mx_records, key=lambda x: x['preference'])

# Global DNS cache instance
dns_cache = DNSCache()

def cached_dns_lookup(func):
    """
    Decorator to add DNS caching to methods that perform DNS lookups
    """
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        # Use the instance's dns_cache
        if not hasattr(self, 'dns_cache'):
            self.dns_cache = DNSCache()
        return func(self, *args, **kwargs)
    return wrapper