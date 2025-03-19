# Performance testing with qperf

## Instructions

```bash
$ docker build -t qperf .
$ docker run -d --rm --name qperf qperf
$ docker exec -it qperf /app/qperf -c localhost
starting client with host localhost, port 18080, runtime 10s, cc reno, iw 10
connection establishment time: 23ms
time to first byte: 26ms
second 0: 4.658 gbit/s (625231449 bytes received)
second 1: 4.757 gbit/s (638432016 bytes received)
second 2: 4.777 gbit/s (641102429 bytes received)
second 3: 4.783 gbit/s (641933333 bytes received)
second 4: 4.742 gbit/s (636401781 bytes received)
second 5: 4.733 gbit/s (635259273 bytes received)
second 6: 4.759 gbit/s (638749763 bytes received)
second 7: 4.773 gbit/s (640599464 bytes received)
second 8: 4.793 gbit/s (643290580 bytes received)
second 9: 4.773 gbit/s (640601954 bytes received)
connection closed
$ docker stop qperf
```

Uses https://github.com/rbruenig/qperf
