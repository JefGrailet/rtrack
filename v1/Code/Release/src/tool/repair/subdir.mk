################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
../src/tool/repair/AnonymousCheckUnit.cpp \
../src/tool/repair/AnonymousChecker.cpp \
../src/tool/repair/RouteRepairer.cpp

OBJS += \
./src/tool/repair/AnonymousCheckUnit.o \
./src/tool/repair/AnonymousChecker.o \
./src/tool/repair/RouteRepairer.o

CPP_DEPS += \
./src/tool/repair/AnonymousCheckUnit.d \
./src/tool/repair/AnonymousChecker.d \
./src/tool/repair/RouteRepairer.d


# Each subdirectory must supply rules for building sources it contributes
src/tool/repair/%.o: ../src/tool/repair/%.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C++ Compiler'
	g++ -m32 -O3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


