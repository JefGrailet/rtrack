################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../src/tool/prescanning/NetworkPrescanningUnit.cpp \
../src/tool/prescanning/NetworkPrescanner.cpp

OBJS += \
./src/tool/prescanning/NetworkPrescanningUnit.o \
./src/tool/prescanning/NetworkPrescanner.o

CPP_DEPS += \
./src/tool/prescanning/NetworkPrescanningUnit.d \
./src/tool/prescanning/NetworkPrescanner.d


# Each subdirectory must supply rules for building sources it contributes
src/tool/prescanning/%.o: ../src/tool/prescanning/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -m32 -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


