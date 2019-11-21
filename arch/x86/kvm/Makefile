# SPDX-License-Identifier: GPL-2.0

ccflags-y += -Iarch/x86/kvm

CFLAGS_x86.o := -I.
CFLAGS_svm.o := -I.
CFLAGS_vmx.o := -I.

KVM := ../../../virt/kvm

kvm-y			+= $(KVM)/kvm_main.o $(KVM)/coalesced_mmio.o \
				$(KVM)/eventfd.o $(KVM)/irqchip.o $(KVM)/vfio.o
kvm-$(CONFIG_KVM_ASYNC_PF)	+= $(KVM)/async_pf.o

kvm-y			+= x86.o mmu.o emulate.o i8259.o irq.o lapic.o \
			   i8254.o ioapic.o irq_comm.o cpuid.o pmu.o mtrr.o \
			   hyperv.o page_track.o debugfs.o

kvm-$(CONFIG_KVM_VGPU) += kvm_vgpu.o kvm_vgpu_init.o kvm_vgpu_policy.o \
				          kvm_vgpu_measure.o

kvm-$(CONFIG_KVM_VGPU) += kvm_vgpu.o kvm_vgpu_init.o kvm_vgpu_policy.o \
				          kvm_vgpu_measure.o \
				          ava_policy/command_rate.o \
				          ava_policy/device_time.o \
				          ava_policy/device_time_hp.o \
				          ava_policy/device_memory.o \
				          ava_policy/device_memory_limit.o \
						  ava_policy/qat_throughput.o

kvm-intel-y		+= vmx.o pmu_intel.o
kvm-amd-y		+= svm.o pmu_amd.o

obj-$(CONFIG_KVM)	+= kvm.o
obj-$(CONFIG_KVM_INTEL)	+= kvm-intel.o
obj-$(CONFIG_KVM_AMD)	+= kvm-amd.o
