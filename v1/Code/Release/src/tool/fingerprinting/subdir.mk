################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../src/tool/fingerprinting/FingerprintingUnit.cpp \
../src/tool/fingerprinting/FingerprintMaker.cpp

OBJS += \
./src/tool/fingerprinting/FingerprintingUnit.o \
./src/tool/fingerprinting/FingerprintMaker.o

CPP_DEPS += \
./src/tool/fingerprinting/FingerprintingUnit.d \
./src/tool/fingerprinting/FingerprintMaker.d


# Each subdirectory must supply rules for building sources it contributes
src/tool/fingerprinting/%.o: ../src/tool/fingerprinting/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -m32 -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


