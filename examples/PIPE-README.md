Send data streams over QUIC (Quicly)
===

Using the `pipeclient` and `pipeserver` binaries you can esaly send data streams (ex: live video) over QUIC

How to test it
---

- Install & compile the code, you can follow the [readme](../README.md) instructions

- Generate the certs in the `/tmp` dir:
```
mkdir -p tmp
openssl req -nodes -new -x509  -keyout tmp/server.key -out tmp/server.crt
```

- To run the server
```
./examples-pipeserver -c ../tmp/server.crt -k ../tmp/server.key -p 4433 > myReceivedFile.bin
```

- To run the client
```
cat myfile.bin | ./examples-pipeclient
```

- Check files
```
diff myfile.bin myReceivedFile.bin
```

Example with video (Assumes `ffmpeg` and `ffplay` installed)
---

- To run the server:
```
./examples-pipeserver -c ../tmp/server.cert -k ../tmp/server.key -p 4433 | ffplay -
```

- To run the client:
```
ffmpeg -re -f lavfi -i smptebars=duration=30:size=320x200:rate=30 -f lavfi -re -i sine=frequency=1000:duration=30:sample_rate=48000 -pix_fmt yuv420p -c:v libx264 -b:v 180k -g 60 -keyint_min 60 -profile:v baseline -preset veryfast -c:a aac -b:a 96k -vf "drawtext=fontfile=/Library/Fonts/Arial.ttf: text=\'Local time %{localtime\: %Y\/%m\/%d %H.%M.%S} (%{n})\': x=10: y=10: fontsize=16: fontcolor=white: box=1: boxcolor=0x00000099" -f mpegts - | ./examples-pipeclient
```

Note: The previous command will work on MACos, but if you have problems with `lavfi` filter or with the fonts path you can use the following one:
```
ffmpeg -re -i myVideoFile.mp4 -c copy -f mpegts - | ./examples-pipeclient
```

Now you should see live video!!!