################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../src/tool/ToolEnvironment.cpp

OBJS += \
./src/tool/ToolEnvironment.o

CPP_DEPS += \
./src/tool/ToolEnvironment.d


# Each subdirectory must supply rules for building sources it contributes
src/tool/%.o: ../src/tool/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -m32 -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


