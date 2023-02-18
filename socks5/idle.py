# Requires pyto https://pyto.app/

from UIKit import UIApplication
import mainthread


@mainthread.mainthread
def disable_idle_timer():
    UIApplication.sharedApplication.setIdleTimerDisabled_(True)