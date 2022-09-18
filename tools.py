from timeit import default_timer as timer

def timefunc(func):
    def inner(*args, **kwargs):
        start = timer()
        results = func(*args, **kwargs)
        end = timer()
        message = 'Scanning the target completed in {} seconds'.format(end - start)
        print(message)
        return results
    return inner
