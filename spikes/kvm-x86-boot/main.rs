// x86_64 Linux boot under KVM (64-bit entry) with live serial + SIGALRM watchdog.
use kvm_bindings::{kvm_userspace_memory_region, kvm_segment, KVM_MAX_CPUID_ENTRIES};
use kvm_ioctls::{Kvm, VcpuExit};
use std::io::{Read, Write};

const MEM: usize = 512 << 20;
const PML4: u64 = 0x1000; const PDPT: u64 = 0x2000; const PD: u64 = 0x3000; const GDT: u64 = 0x4000;
const BOOTP: u64 = 0x1_0000; const CMDLINE: u64 = 0x2_0000; const KERNEL: u64 = 0x10_0000;
const CMD: &[u8] = b"earlyprintk=serial,ttyS0,115200 console=ttyS0 acpi=off pci=off reboot=t panic=-1 nokaslr\0";

fn put<T: Copy>(m: *mut u8, off: u64, v: T) { unsafe { std::ptr::write_unaligned(m.add(off as usize) as *mut T, v) }; }
extern "C" fn on_alarm(_: libc::c_int) {}

fn main() {
    let path = std::env::args().nth(1).unwrap_or("/boot/vmlinuz-6.1.0-47-amd64".into());
    let mut bz = Vec::new(); std::fs::File::open(&path).unwrap().read_to_end(&mut bz).unwrap();
    let setup_sects = { let s = bz[0x1f1]; if s == 0 { 4u32 } else { s as u32 } };
    let pm = &bz[((setup_sects + 1) * 512) as usize..];
    eprintln!("bzImage {} ({} bytes)", path, bz.len());

    let kvm = Kvm::new().unwrap();
    let vm = kvm.create_vm().unwrap();
    vm.set_tss_address(0xffff_b000).unwrap();
    vm.create_irq_chip().unwrap();
    vm.create_pit2(kvm_bindings::kvm_pit_config::default()).unwrap(); // i8254 PIT: timer ticks
    let m = unsafe { libc::mmap(std::ptr::null_mut(), MEM, libc::PROT_READ|libc::PROT_WRITE, libc::MAP_SHARED|libc::MAP_ANONYMOUS, -1, 0) as *mut u8 };
    put::<u64>(m, PML4, PDPT | 0x3); put::<u64>(m, PDPT, PD | 0x3);
    for i in 0..512u64 { put::<u64>(m, PD + i*8, (i << 21) | 0x83); }
    put::<u64>(m, GDT, 0); put::<u64>(m, GDT+8, 0); put::<u64>(m, GDT+16, 0x00af_9a00_0000_ffff); put::<u64>(m, GDT+24, 0x00cf_9200_0000_ffff);
    unsafe {
        std::ptr::copy_nonoverlapping(pm.as_ptr(), m.add(KERNEL as usize), pm.len());
        std::ptr::copy_nonoverlapping(CMD.as_ptr(), m.add(CMDLINE as usize), CMD.len());
        std::ptr::copy_nonoverlapping(bz.as_ptr().add(0x1f1), m.add(BOOTP as usize + 0x1f1), 0x268 - 0x1f1);
    }
    put::<u8>(m, BOOTP+0x210, 0xff);
    put::<u8>(m, BOOTP+0x211, bz[0x211] | 0x01); // preserve image loadflags + LOADED_HIGH
    put::<u32>(m, BOOTP+0x228, CMDLINE as u32);
    // e820: usable 0..640 KiB, then 1 MiB..end of RAM (leaves the BIOS hole)
    put::<u64>(m, BOOTP+0x2d0, 0); put::<u64>(m, BOOTP+0x2d8, 0x9_fc00); put::<u32>(m, BOOTP+0x2e0, 1);
    put::<u64>(m, BOOTP+0x2d0+20, KERNEL); put::<u64>(m, BOOTP+0x2d8+20, MEM as u64 - KERNEL); put::<u32>(m, BOOTP+0x2e0+20, 1);
    put::<u8>(m, BOOTP+0x1e8, 2);
    // optional initramfs: place top-down, clear of the kernel's init_size footprint
    if let Ok(rdpath) = std::env::var("MVM_INITRD") {
        let mut rd = Vec::new(); std::fs::File::open(&rdpath).unwrap().read_to_end(&mut rd).unwrap();
        let init_size = u32::from_le_bytes(bz[0x260..0x264].try_into().unwrap()) as u64;
        let footprint = (pm.len() as u64).max(init_size);
        let floor = (KERNEL + footprint + 0xfff) & !0xfff;
        let top = (MEM as u64).min(0x8000_0000);
        let addr = (top - rd.len() as u64) & !0xfff;
        assert!(addr >= floor, "initrd doesn't fit");
        unsafe { std::ptr::copy_nonoverlapping(rd.as_ptr(), m.add(addr as usize), rd.len()); }
        put::<u32>(m, BOOTP+0x218, addr as u32);
        put::<u32>(m, BOOTP+0x21c, rd.len() as u32);
        eprintln!("initrd {} bytes @ {:#x}", rd.len(), addr);
    }
    let region = kvm_userspace_memory_region { slot: 0, guest_phys_addr: 0, memory_size: MEM as u64, userspace_addr: m as u64, flags: 0 };
    unsafe { vm.set_user_memory_region(region).unwrap(); }

    let mut vcpu = vm.create_vcpu(0).unwrap();
    let cpuid = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES).unwrap();
    vcpu.set_cpuid2(&cpuid).unwrap();
    let mut s = vcpu.get_sregs().unwrap();
    let cs = kvm_segment { base:0, limit:0xfffff, selector:0x10, type_:0xb, present:1, dpl:0, db:0, s:1, l:1, g:1, avl:0, unusable:0, padding:0 };
    let ds = kvm_segment { base:0, limit:0xfffff, selector:0x18, type_:0x3, present:1, dpl:0, db:1, s:1, l:0, g:1, avl:0, unusable:0, padding:0 };
    s.cs=cs; s.ds=ds; s.es=ds; s.ss=ds; s.fs=ds; s.gs=ds; s.gdt.base=GDT; s.gdt.limit=0x1f;
    s.cr0=0x8000_0001; s.cr3=PML4; s.cr4=0x20; s.efer=0x500;
    vcpu.set_sregs(&s).unwrap();
    let mut r = vcpu.get_regs().unwrap();
    r.rip=KERNEL+0x200; r.rsi=BOOTP; r.rflags=2;
    vcpu.set_regs(&r).unwrap();

    // SIGALRM watchdog: interrupts a hung KVM_RUN so we always terminate.
    unsafe { libc::signal(libc::SIGALRM, on_alarm as usize); libc::alarm(30); }
    let mut n = 0usize;
    let so = std::io::stdout();
    loop {
        match vcpu.run() {
            Ok(VcpuExit::IoOut(0x3f8, d)) => { let mut h = so.lock(); let _ = h.write_all(d); let _ = h.flush(); n += d.len(); }
            Ok(VcpuExit::IoIn(0x3fd, d)) => { for b in d.iter_mut() { *b = 0x60; } }
            Ok(VcpuExit::IoIn(_, d)) => { for b in d.iter_mut() { *b = 0; } }
            Ok(VcpuExit::IoOut(_, _)) => {}
            Ok(VcpuExit::Hlt) => { /* idle: await next timer tick */ }
            Ok(o) => { eprintln!("\n[exit {:?}]", o); break; }
            Err(e) => { eprintln!("\n[run err {:?} — watchdog/interrupt]", e); break; }
        }
    }
    if let Ok(rr) = vcpu.get_regs() { eprintln!("[regs] rip={:#x} cr2-fault?", rr.rip); }
    eprintln!("---- {} serial bytes ----", n);
}
