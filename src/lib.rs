use core::panic;

#[repr(C)]
#[derive(Debug)]
pub struct Block {
    len: usize,
    nxt: usize,
}
fn dump_heap(mem: &mut [usize]) {
    let addr_to_block = |mem: &mut [usize], addr: usize| {
        return Block {
            len: mem[addr],
            nxt: mem[addr + 1],
        };
    };

    let header = addr_to_block(mem, 0);
    let mut cur = addr_to_block(mem, header.nxt);
	println!("{:#x?}: {:?}", 0, header);
    let mut curaddr = header.nxt;
    while curaddr != 0 {
		println!("{:#x?}: {:?}", curaddr, cur);
        curaddr = cur.nxt;
        cur = addr_to_block(mem, curaddr);
    }
}
pub fn alloc(mem: &mut [usize], len: usize) -> usize {
    let addr_to_block = |mem: &mut [usize], addr: usize| {
        return Block {
            len: mem[addr],
            nxt: mem[addr + 1],
        };
    };
    let sync_block = |mem: &mut [usize], addr: usize, blk: Block| {
        mem[addr] = blk.len;
        mem[addr + 1] = blk.nxt;
    };
    let mut header = addr_to_block(mem, 0);
    if header.len > len {
        // noice
        // we get to use header
        header.len -= len;
        let res = header.len;
        sync_block(mem, 0, header);
        return res;
    }

    let mut cur = addr_to_block(mem, header.nxt);
    let mut curaddr = header.nxt;
    while curaddr != 0 {
        if cur.len > len + 2 {
            cur.len -= len;
            let res = cur.len + curaddr;
            sync_block(mem, curaddr, cur);
            return res;
        }
        curaddr = cur.nxt;
        cur = addr_to_block(mem, curaddr);
    }

    dump_heap(mem);
    panic!("Failed to alloc {} bytes", len);
}

pub fn free(mem: &mut [usize], addr: usize, len: usize) {
    let addr_to_block = |mem: &mut [usize], addr: usize| {
        return Block {
            len: mem[addr],
            nxt: mem[addr + 1],
        };
    };
    let sync_block = |mem: &mut [usize], addr: usize, blk: Block| {
        mem[addr] = blk.len;
        mem[addr + 1] = blk.nxt;
    };

    let mut cur = addr_to_block(mem, 0);
    let mut curaddr = 0;
    let mut blk0skp = true;
    let mut prev = 0;
    while curaddr != 0 || blk0skp {
        blk0skp = false;
        // two-way merge
        if curaddr + cur.len + len == cur.nxt && curaddr + cur.len == addr {
            let oldnxt = cur.nxt;
            let oldblk = addr_to_block(mem, oldnxt);
            cur.nxt = oldblk.nxt;
            cur.len += len + oldblk.len;
            sync_block(mem, curaddr, cur);
            return;
        } // merge back
        if curaddr + cur.len == addr {
            cur.len += len;
            sync_block(mem, curaddr, cur);
            return;
        }
        // merge forward
        if addr + len == cur.nxt {
            let oldnxt = cur.nxt;
            cur.nxt = addr;
            let oldblk = addr_to_block(mem, oldnxt);
            let newblk = Block {
                len: oldblk.len + len,
                nxt: oldblk.nxt,
            };
            sync_block(mem, curaddr, cur);
            sync_block(mem, addr, newblk);
            return;
        }
        // fallback: insert
        if (cur.nxt > addr && cur.nxt != addr + len) || cur.nxt == 0 {
            let new_block = Block { len, nxt: cur.nxt };
            cur.nxt = addr;
            sync_block(mem, curaddr, cur);
            sync_block(mem, addr, new_block);
            return;
        }
        curaddr = cur.nxt;
        prev = curaddr;
        cur = addr_to_block(mem, curaddr);
    }
    let mut cur = addr_to_block(mem, prev);
    let curaddr = prev;
    let new_block = Block { len, nxt: cur.nxt };
    cur.nxt = addr;
    sync_block(mem, curaddr, cur);
    sync_block(mem, addr, new_block);
}
