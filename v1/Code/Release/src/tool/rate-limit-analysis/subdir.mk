################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../src/tool/rate-limit-analysis/ProbeUnit.cpp \
../src/tool/rate-limit-analysis/RoundScheduler.cpp

OBJS += \
./src/tool/rate-limit-analysis/ProbeUnit.o \
./src/tool/rate-limit-analysis/RoundScheduler.o

CPP_DEPS += \
./src/tool/rate-limit-analysis/ProbeUnit.d \
./src/tool/rate-limit-analysis/RoundScheduler.d


# Each subdirectory must supply rules for building sources it contributes
src/tool/rate-limit-analysis/%.o: ../src/tool/rate-limit-analysis/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -m32 -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


