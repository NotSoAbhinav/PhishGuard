cache = {}

def get_cached(url):
    return cache.get(url)

def set_cache(url, data):
    cache[url] = data

def clear_cache():
    cache.clear()
    print("Prediction cache cleared.")