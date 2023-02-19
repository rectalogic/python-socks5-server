# Requires pyto https://pyto.app/

from UIKit import UIApplication  # type: ignore[import]
import mainthread  # type: ignore[import]


@mainthread.mainthread
def disable_idle_timer():
    UIApplication.sharedApplication.setIdleTimerDisabled_(True)