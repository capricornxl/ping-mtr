# -*- coding: utf-8 -*-
import sys
import threading


class KillThreading(threading.Thread):
    def __init__(self, *args, **kwargs):
        threading.Thread.__init__(self, *args, **kwargs)
        self.killed = False

    def start(self):
        """Start the thread."""
        self.__run_backup = self.run
        self.run = self.__run  # Force the Thread to install our trace.
        threading.Thread.start(self)

    def __run(self):
        """Hacked run function, which installs the
        trace."""
        sys.settrace(self.globaltrace)
        self.__run_backup()
        self.run = self.__run_backup

    def globaltrace(self, frame, why, arg):
        if why == 'call':
            return self.localtrace
        else:
            return None

    def localtrace(self, frame, why, arg):
        if self.killed:
            if why == 'line':
                raise SystemExit()
        return self.localtrace

    def kill(self):
        self.killed = True


def runtimer(runtime):
    """
    运行时长定时器
    :return: runtimer stoped 终止执行
    """

    def timeout_decorator(func):
        def _new_func(oldfunc, result, oldfunc_args, oldfunc_kwargs):
            result.append(oldfunc(*oldfunc_args, **oldfunc_kwargs))

        def _(*args, **kwargs):
            result = []
            new_kwargs = {
                'oldfunc': func,
                'result': result,
                'oldfunc_args': args,
                'oldfunc_kwargs': kwargs
            }
            thd = KillThreading(target=_new_func, args=(), kwargs=new_kwargs)
            thd.start()
            thd.join(runtime)
            thd.kill()
            killed = thd.is_alive()
            if killed:
                return str('runtimer stoped')
            else:
                return str('runtimer stoped failed')

        _.__name__ = func.__name__
        _.__doc__ = func.__doc__
        return _

    return timeout_decorator