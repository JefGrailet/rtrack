################################################################################
# Automatically-generated file. Do not edit!
################################################################################

-include ../makefile.init

RM := rm -rf

# All of the sources participating in the build are defined here
-include sources.mk
-include src/common/utils/subdir.mk
-include src/common/thread/subdir.mk
-include src/common/random/subdir.mk
-include src/common/inet/subdir.mk
-include src/common/exception/subdir.mk
-include src/common/date/subdir.mk
-include src/prober/structure/subdir.mk
-include src/prober/icmp/subdir.mk
-include src/prober/udp/subdir.mk
-include src/prober/tcp/subdir.mk
-include src/prober/exception/subdir.mk
-include src/prober/subdir.mk
-include src/tool/structure/subdir.mk
-include src/tool/prescanning/subdir.mk
-include src/tool/traceroute/subdir.mk
-include src/tool/repair/subdir.mk
-include src/tool/postprocessing/subdir.mk
-include src/tool/fingerprinting/subdir.mk
-include src/tool/rate-limit-analysis/subdir.mk
-include src/tool/utils/subdir.mk
-include src/tool/subdir.mk
-include src/subdir.mk
-include subdir.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(C++_DEPS)),)
-include $(C++_DEPS)
endif
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
ifneq ($(strip $(CC_DEPS)),)
-include $(CC_DEPS)
endif
ifneq ($(strip $(CPP_DEPS)),)
-include $(CPP_DEPS)
endif
ifneq ($(strip $(CXX_DEPS)),)
-include $(CXX_DEPS)
endif
ifneq ($(strip $(C_UPPER_DEPS)),)
-include $(C_UPPER_DEPS)
endif
endif

-include ../makefile.defs

# Add inputs and outputs from these tool invocations to the build variables 

# All Target
all: rtrack

# Tool invocations
rtrack: $(OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C++ Linker'
	g++ -m32  -o "rtrack" $(OBJS) $(USER_OBJS) $(LIBS)
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) $(OBJS)$(C++_DEPS)$(C_DEPS)$(CC_DEPS)$(CPP_DEPS)$(EXECUTABLES)$(CXX_DEPS)$(C_UPPER_DEPS) rtrack
	-@echo ' '

.PHONY: all clean dependents
.SECONDARY:

-include ../makefile.targets
