```bash
(TEMPLATE=hello; NAME=demo; cr cleanup --all; cr stop $NAME; cr template build $TEMPLATE --force --snapshot; cr run --template $TEMPLATE --name $NAME; cr logs -f $NAME;)
```

```bash
(TEMPLATE=openclaw; NAME=oc; cr cleanup --all; cr stop $NAME; cr template build $TEMPLATE --force --snapshot; cr run --template $TEMPLATE --name $NAME -v nix/examples/openclaw/config:/mnt/config -v nix/examples/openclaw/secrets:/mnt/secrets -p 3000:3000; cr forward $NAME & cr logs -f $NAME;)
```

---

We want these boots to be as FAST as possible. I need these microvms to be as small as possible. That's part of the point of this library

---

