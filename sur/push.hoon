::  sur/push: web push notification types
::
::  p256dh and auth are MSB-first atoms (crypto convention)
::
|%
+$  subscription  [endpoint=@t p256dh=@ auth=@]
+$  push-config  [private-key=@ public-key=@ sub=@t]
+$  push-message
  $:  title=@t
      body=@t
      icon=(unit @t)
      url=(unit @t)
      tag=(unit @t)
  ==
+$  delivery-status  ?(%pending %sent %failed %expired %gone)
+$  delivery
  $:  sub-id=@ta
      title=@t
      sent-at=@da
      =delivery-status
  ==
+$  pusher-state
  $:  config=(unit push-config)
      subs=(map @ta subscription)
      sends=(list delivery)
  ==
--
