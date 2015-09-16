#include "isr.h"
#include "io.h"
#include "kernel.h"

#define rdtscll(val) __asm__ __volatile__("rdtsc" : "=A" (val))

typedef struct {
  u8_t sig[4];
  u32_t length;
  u8_t revision;
  u8_t checksum;
  u8_t oemid[6];
  u64_t oemtableid;
  u32_t oemrevision;
  u8_t creatorid[4];
  u32_t creatorrevision;
  struct {
    u8_t hwrev;
    u8_t ncomp :5;
    u8_t count_size_cap :1;
    u8_t reserved :1;
    u8_t legacy_irq :1;
    u16_t pci_vendor;
  } blockid;
  struct {
    u8_t space_id;
    u8_t reg_bit_width;
    u8_t reg_bit_offset;
    u8_t reserved;
    u64_t address;
  } address;
  u8_t number;
  u16_t minimumclocktick;
  u8_t oemattribute;
} __attribute__((packed)) HPET_tab;

typedef volatile struct {
	const struct {
		u8_t rev_id;
		u8_t num_tim_cap :5;
		u8_t count_size_cap :1;
		u8_t reserved :1;
		u8_t leg_route_cap :1;
		u16_t vendor_id;
		u32_t counter_clk_period;
	} cap;
	u64_t res0;
	struct {
		u8_t enable_cnf :1;
		u8_t leg_rt_cnf :1;
		u8_t res1 : 6;
		u8_t res2;
		u16_t res3;
		u32_t res4;
	} config;
	u64_t res1;
	u64_t interrupt;
	u64_t res2;
	u64_t counter;
	u64_t res3;
	struct {
		struct {
			u8_t res1 :1;
			u8_t int_type_cnf :1;
			u8_t int_enb_cnf :1;
			u8_t type_cnf :1;
			u8_t per_int_cap :1;
			u8_t size_cap :1;
			u8_t val_set_cnf :1;
			u8_t res2 :1;
			u8_t mode32_cnf :1;
			u8_t int_route_cnf: 5;
			u8_t fsb_en_cnf: 1;
			u8_t fsb_int_del_cap: 1;
			u16_t res3;
			u32_t int_route_cap;
		} config;
		
		u64_t compare;
		u64_t interrupt;
		u64_t reserved;
	} timers[3];
} __attribute__((packed)) HPET;

static HPET *hpet;

static u32_t tick = 0;
static int current_type = TIMER_FREQUENCY;
static u64_t oneshot_target = 0;
static u64_t timerout = 0;

void
timer_print(int n)
{
	printk("--- Timer %d:\n", n);
	printk("--- int_type_cnf int_enb_cnf type_cnf per_int_cap size_cap val_set_cnf 32mode_cnf int_route_cnf fsb_en_cnf fsb_int_del_cap int_route_cap\n");
	printk("--- %12u %11u %8u %11u %8u %11u %10u %13u %10u %15u %13u\n",
		hpet->timers[n].config.int_type_cnf,
		hpet->timers[n].config.int_enb_cnf,
		hpet->timers[n].config.type_cnf,
		hpet->timers[n].config.per_int_cap,
		hpet->timers[n].config.size_cap,
		hpet->timers[n].config.val_set_cnf,
		hpet->timers[n].config.mode32_cnf,
		hpet->timers[n].config.int_route_cnf,
		hpet->timers[n].config.fsb_en_cnf,
		hpet->timers[n].config.fsb_int_del_cap,
		hpet->timers[n].config.int_route_cap);
}

void
timer_callback(struct registers *regs)
{
    tick++;
    u64_t cycle;
    rdtscll(cycle);

    if (tick < 25) {
        printk("Tick: %2u @%10llu (%10llu) ((%10llu))\n", tick, cycle, hpet->counter, ((unsigned long long*)hpet)[30]);
	timerout *= 10;
    }

    if (current_type == TIMER_ONESHOT) {
         u64_t timer;
         rdtscll(timer);
         timer_set(TIMER_FREQUENCY, DEFAULT_FREQUENCY);
    }

    timer_set(TIMER_ONESHOT, timerout);
    hpet->interrupt = 1;
}

void
timer_set(int timer_type, u64_t cycles)
{
    hpet->config.enable_cnf = 0;
    hpet->counter = 0;
    /* printk("Setting timer 0:\n"); */
    /* printk("- Before:\n"); */
    /* timer_print(0); */
    hpet->timers[0].config.val_set_cnf = 1;
    if (timer_type == TIMER_ONESHOT) {
    	hpet->timers[0].compare = cycles + hpet->counter;
    } else {
	hpet->timers[0].config.type_cnf = 1;
	hpet->timers[0].compare = cycles;
    }
    current_type = timer_type;
    hpet->timers[0].config.int_enb_cnf = 1;
    /* printk("- After:\n"); */
    /* timer_print(0); */
    hpet->interrupt = 1;
    hpet->config.enable_cnf = 1;
}

u64_t
timer_find_hpet(void *timer)
{
	u32_t i;
	unsigned char sum = 0;

	HPET_tab *hpetaddr = timer;
	printk("Initiliazing HPET @ %p\n", hpetaddr);
	printk("-- Signature:  %c%c%c%c\n", hpetaddr->sig[0], hpetaddr->sig[1], hpetaddr->sig[2], hpetaddr->sig[3]);
	printk("-- Length:     %d\n", hpetaddr->length);
	printk("-- Revision:   %d\n", hpetaddr->revision);
	printk("-- Checksum:   %x\n", hpetaddr->checksum);
	printk("-- OEM ID:     %c%c%c%c%c%c\n", hpetaddr->oemid[0], hpetaddr->oemid[1], hpetaddr->oemid[2], hpetaddr->oemid[3], hpetaddr->oemid[4], hpetaddr->oemid[5]);
	printk("-- OEM Rev:    %d\n", hpetaddr->oemrevision);
	printk("-- Creator ID: %c%c%c%c\n", hpetaddr->creatorid[0], hpetaddr->creatorid[1], hpetaddr->creatorid[2], hpetaddr->creatorid[3]);
	printk("-- CreatorRev: %d\n", hpetaddr->creatorrevision);
	printk("-- HW Revi:    %d\n", hpetaddr->blockid.hwrev);
	printk("-- N Compar:   %d\n", hpetaddr->blockid.ncomp);
	printk("-- Count Size: %d\n", hpetaddr->blockid.count_size_cap);
	printk("-- Reserved:   %d\n", hpetaddr->blockid.reserved);
	printk("-- Legacy IRQ: %d\n", hpetaddr->blockid.legacy_irq);
	printk("-- PCI Vendor: %hx\n", hpetaddr->blockid.pci_vendor);
	printk("-- AddrSpace:  %s (%d)\n", hpetaddr->address.space_id ? "I/O" : "Memory", hpetaddr->address.space_id);
	printk("-- Bit Width:  %d\n", hpetaddr->address.reg_bit_width);
	printk("-- Bit Offset: %d\n", hpetaddr->address.reg_bit_offset);
	printk("-- Reserved:   %d\n", hpetaddr->address.reserved);
	printk("-- Address:    %llx\n", hpetaddr->address.address);
	printk("-- Number:     %d\n", hpetaddr->number);
	printk("-- Min Tick:   %hu\n", hpetaddr->minimumclocktick);
	printk("-- OEM Attr:   %x\n", hpetaddr->oemattribute);
	for (i = 0; i < hpetaddr->length; i++) {
		sum += ((unsigned char*)hpetaddr)[i];
	}
	if (sum == 0) {
		printk("-- Checksum is OK\n");
		hpet = (HPET*)((u32_t)(hpetaddr->address.address & 0xffffffff));
		return hpetaddr->address.address;
	}

	printk("-- Invalid checksum (%d)\n", sum);
	return 0;
}

void
timer_set_hpet_page(u32_t page)
{
	int i;
	hpet = (HPET*)(page * (1 << 22) | ((u32_t)hpet & ((1<<22)-1)));
	unsigned char *b = (unsigned char *)hpet;
	hpet->config.enable_cnf = 1;
	/* hpet->config.leg_rt_cnf = 1; */
	printk("Set HPET @ %p\n", hpet);
	printk("-- Rev ID:           %x\n", hpet->cap.rev_id & 0xff);
	printk("-- Num_Tim_Cap:      %u\n", hpet->cap.num_tim_cap);
	printk("-- Count_Size_Cap:   %u\n", hpet->cap.count_size_cap);
	printk("-- Leg_Route_Cap:    %u\n", hpet->cap.leg_route_cap & 1);
	printk("-- Vendor ID:        %hx\n", hpet->cap.vendor_id);
	printk("-- Period:           %d fs\n", hpet->cap.counter_clk_period);
	printk("-- Enable CNF:       %d\n", hpet->config.enable_cnf);
	printk("-- Leg_RT_CNF:       %d\n", hpet->config.leg_rt_cnf);
	printk("-- Interrupt Status: %llx\n", hpet->interrupt);
	printk("-- Counter:          %llx\n", hpet->counter);

	for (i = 0; i <= 0xff; i++) {
		printk("%02x%c", b[i] & 0xff, i % 16 == 15 ? '\n' : ' '); 
	}
}


void
timer_init(int timer_type, u64_t cycles)
{
    printk("Enabling timer @ %p\n", hpet);
    register_interrupt_handler(IRQ0, timer_callback);
    register_interrupt_handler(IRQ2, timer_callback);

    timer_set(timer_type, cycles);
    timerout = cycles;

    printk("T0: %lld\n", hpet->counter);
    printk("T1: %lld\n", hpet->counter);

    __asm__("sti");
    while (tick < 15) { __asm__("hlt"); }
    __asm__("cli");
}
