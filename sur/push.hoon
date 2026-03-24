::  sur/push: web push notification types
::
::  p256dh and auth are MSB-first atoms (crypto convention)
::
|%
+$  subscription  [endpoint=@t p256dh=@ auth=@]
+$  tagged-sub  [sub=subscription tags=(set term)]
+$  push-config  [private-key=@ public-key=@ sub=@t]
+$  push-message
  $:  title=@t
      body=@t
      icon=(unit @t)
      url=(unit @t)
      tag=(unit @t)
  ==
+$  push-send
  $:  targets=(set @p)    ::  specific ships (empty = all subscribed)
      tags=(set term)     ::  filter by sub tags (empty = no filtering)
      exclude=(set @p)    ::  remove these ships from recipients
      msg=push-message
  ==
+$  push-subscribe    [who=@p id=@ta sub=subscription tags=(set term)]
+$  push-unsubscribe  [who=@p id=@ta]
+$  push-set-tags     [who=@p id=@ta tags=(set term)]
+$  delivery-status  ?(%pending %sent %failed %expired %gone)
+$  send-key  [ship=@p sub-id=@ta notif-id=@ud]
+$  delivery
  $:  title=@t
      sent-at=@da
      =delivery-status
  ==
+$  pusher-state
  $:  config=(unit push-config)
      subs=(map @p (map @ta tagged-sub))
      send-order=(list send-key)
      sends=(map send-key delivery)
      next-id=@ud
  ==
--
