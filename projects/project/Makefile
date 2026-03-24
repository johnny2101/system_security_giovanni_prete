.POSIX:

export PLATFORM   ?=qemu_virt4
export ROOT       :=${abspath ../..}
export BUILD      :=${abspath build/${PLATFORM}}
export S3K_CONF_H :=${abspath s3k_conf.h}

include ${ROOT}/tools.mk

APPS=monitor app
MONITOR_CPPFLAGS ?=
CFA_STRICT_ENFORCEMENT ?= 0
MONITOR_CPPFLAGS += -DCFA_STRICT_ENFORCEMENT=${CFA_STRICT_ENFORCEMENT}
MONITOR_CFG_STAMP := ${BUILD}/.monitor_cfa_strict

LOG_RECIPE = @printf "\033[1;36m[recipe]\033[0m \033[1m%s\033[0m\n" "$@"

ELFS:=${patsubst %, ${BUILD}/%.elf, kernel ${APPS}}
JOP_ELFS:=${patsubst %, ${BUILD}/%.elf, kernel monitor jop}

all: kernel ${APPS}

clean:
	$(LOG_RECIPE)
	rm -rf ${BUILD}

common:
	$(LOG_RECIPE)
	@${MAKE} -C ${ROOT}/common

kernel: common
	$(LOG_RECIPE)
	@${MAKE} -C ${ROOT}/kernel

policy_static: app
	$(LOG_RECIPE)
	@printf "GEN\tmonitor/policy.h\n"
# 	@python3 app/policy_to_consts.py

policy_dynamic: app policy_static
	$(LOG_RECIPE)
	@printf "GEN\tmonitor/policy.h\n"
	@rm -f qemu.log
	@gtimeout 10s make qemu 2>&1 | tee qemu.log || true
	@python3 merge_cfg.py cfa_policy.json qemu.log
	@python3 app/policy_to_consts.py -d
	@make clean

monitor: common policy_static
	$(LOG_RECIPE)
	@mkdir -p ${BUILD}
	@if [ ! -f ${MONITOR_CFG_STAMP} ] || [ "`cat ${MONITOR_CFG_STAMP}`" != "${CFA_STRICT_ENFORCEMENT}" ]; then \
		rm -rf ${BUILD}/monitor ${BUILD}/monitor.elf ${BUILD}/monitor.bin ${BUILD}/monitor.hex ${BUILD}/monitor.da; \
		echo ${CFA_STRICT_ENFORCEMENT} > ${MONITOR_CFG_STAMP}; \
	fi
	@${MAKE} -f ../build.mk PROGRAM=$@ INC="${MONITOR_CPPFLAGS}"

monitor_strict: common policy_dynamic
	$(LOG_RECIPE)
	@mkdir -p ${BUILD}
	@if [ ! -f ${MONITOR_CFG_STAMP} ] || [ "`cat ${MONITOR_CFG_STAMP}`" != "${CFA_STRICT_ENFORCEMENT}" ]; then \
		rm -rf ${BUILD}/monitor ${BUILD}/monitor.elf ${BUILD}/monitor.bin ${BUILD}/monitor.hex ${BUILD}/monitor.da; \
		echo ${CFA_STRICT_ENFORCEMENT} > ${MONITOR_CFG_STAMP}; \
	fi
	@${MAKE} -f ../build.mk PROGRAM=monitor INC="${MONITOR_CPPFLAGS}"


app: common llvm-pass/CFAGeneratorPass.dylib
	$(LOG_RECIPE)
	@mkdir -p ${BUILD}/app
	@printf "CLANG\t$< -> app/main.ll\n"
	@/opt/homebrew/opt/llvm/bin/clang -O1 -S -emit-llvm --target=riscv64 -march=rv64imac -mabi=lp64 -mcmodel=medany -DPLATFORM_${PLATFORM} -nostdlib -I${ROOT}/common/inc -I${ROOT}/kernel/inc -I${ROOT}/common/plat -include ${S3K_CONF_H} app/main.c -o ${BUILD}/app/main.ll
	@printf "OPT\tcfa-gen\n"
	@/opt/homebrew/opt/llvm/bin/opt -load-pass-plugin=./llvm-pass/CFAGeneratorPass.dylib -passes="cfa-gen" ${BUILD}/app/main.ll -S -o ${BUILD}/app/main.cfa.ll
	@printf "LLC\tapp/main.o\n"
	@/opt/homebrew/opt/llvm/bin/llc -march=riscv64 -mattr=+m,+a,+c -filetype=obj -relocation-model=static -code-model=medium ${BUILD}/app/main.cfa.ll -o ${BUILD}/app/main.o
	@${MAKE} -f ../build.mk PROGRAM=app C_SRCS="" OBJS="${BUILD}/app/main.o ${ROOT}/common/build/${PLATFORM}/start/start.o"

qemu: kernel ${APPS}
	$(LOG_RECIPE)
	@ELFS="${ELFS}" ${ROOT}/scripts/qemu.sh

qemu-gdb: kernel ${APPS}
	$(LOG_RECIPE)
	@ELFS="${ELFS}" ${ROOT}/scripts/qemu.sh -gdb tcp::3333 -S

gdb: kernel ${APPS}
	$(LOG_RECIPE)
	@ELFS="${ELFS}" ${ROOT}/scripts/gdb.sh

gdb-openocd: kernel ${APPS}
	$(LOG_RECIPE)
	@ELFS="${ELFS}" ${ROOT}/scripts/gdb-openocd.sh

size: ${ELFS}
	$(LOG_RECIPE)
	${SIZE} ${ELFS}


# JOP simulation

jop: common llvm-pass/CFAGeneratorPass.dylib
	$(LOG_RECIPE)
	@mkdir -p ${BUILD}/jop
	@printf "CLANG\t$< -> jop/main.ll\n"
	@/opt/homebrew/opt/llvm/bin/clang -O1 -S -emit-llvm --target=riscv64 -march=rv64imac -mabi=lp64 -mcmodel=medany -DPLATFORM_${PLATFORM} -nostdlib -I${ROOT}/common/inc -I${ROOT}/kernel/inc -I${ROOT}/common/plat -include ${S3K_CONF_H} jop/main.c -o ${BUILD}/jop/main.ll
	@printf "OPT\tcfa-gen\n"
	@/opt/homebrew/opt/llvm/bin/opt -load-pass-plugin=./llvm-pass/CFAGeneratorPass.dylib -passes="cfa-gen" ${BUILD}/jop/main.ll -S -o ${BUILD}/jop/main.cfa.ll
	@printf "LLC\tjop/main.o\n"
	@/opt/homebrew/opt/llvm/bin/llc -march=riscv64 -mattr=+m,+a,+c -filetype=obj -relocation-model=static -code-model=medium ${BUILD}/jop/main.cfa.ll -o ${BUILD}/jop/main.o
	@${MAKE} -f ../build.mk PROGRAM=jop C_SRCS="" OBJS="${BUILD}/jop/main.o ${ROOT}/common/build/${PLATFORM}/start/start.o"


jop_simulation: kernel monitor jop
	$(LOG_RECIPE)
	@ELFS="${JOP_ELFS}" ${ROOT}/scripts/qemu.sh


llvm-pass/CFAGeneratorPass.dylib: llvm-pass/CFAGeneratorPass.cpp llvm-pass/Makefile
	$(LOG_RECIPE)
	@${MAKE} -C llvm-pass



.PHONY: all clean size qemu qemu-gdb gdb kernel common ${APPS} jop jop_simulation
