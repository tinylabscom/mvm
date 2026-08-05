import mvm

mvm.reset_recording()
sandbox = mvm.Sandbox.create("python-3.12", workload_id="bdd-runtime")
sandbox.commands.start(["python", "-c", "print('ok')"])
sandbox.files.write("/app/hello.txt", "hello")
print(mvm.emit_recording_json())
