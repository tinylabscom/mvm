Do we have 100% test coverage? What do we need to test next?

---

When we build a tenant, I don't think we need to make the pool build against a fresh agent, we need to launch it with tenant volumes, but not rebuild the fresh image everytime, I don't think. I think the runtime is what makes the runtime unique. What I mean is we should be able to reuse `aibutler/openclaw` (or the name) for different tenants where the tenant itself isn't aibutler (or `aibutler/openclaw`). That's just the image name. We should be able to reuse that image across any tenant and the tenant should launch an image of openclaw with volumes that are unique to them, not to the image

---

This is a multi-tenant architecture. Each tenant gets their own "customized" microvm version of a template based upon their own secrets and customization, etc. Some templates require multiple types of microvms. For example, openclaw requires a gateway microvm and agent workers. That's considered a pool. So for tenants to get access to their own openclaw, they have access to a pool of microvms. 

Tenant's customizations come from their pool infrastructure so that when a tenant makes a request to our service, if a gateway (the thing that handles inbound requests) isn't running for that tenant, we boot up the microvm and then pass it on to the agent handling device (the other image in openclaw's templated pool) so that from the user's perspective, their setup never changed, but ours optimizes use because we enable sleep/wake infrastructure.

---

Now that we have our nix templates building, we'll want to make it so that they load a tenant's secrets and configuration. How do we start doing that? Where do these secrets and configuration values exist (and they need to be encrypted).

---

I have a `template.toml` in that directory `/Users/auser/work/tinylabs/aibutler/nix/openclaw` -- can we use this to run our build? This way we can have an easy way to make changes to our build in a file?

---

Part of the goal is to have a secure and safe openclaw. I have a few possible resources to investgate how we can safely provide openclaw 

https://safeclaw.io/
@docs/The-OpenClaw-Field-Manual.pdf 
 
 ---

 I think I want to take a different approach. We had a simple development version working without any orchestration work. I think I'd like to take the approach where we keep the simplest version in one repository and then break out the other work in a sibling repository with the orchestrator.

That way we can have a simplest version working in a single repo and then have the management work, which is more complex

---

```bash
cr stop swift; cr template build openclaw --force; cr run --template openclaw --name swift; cr logs -f swift;
```