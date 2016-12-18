################################################################################
# Automatically-generated file. Do not edit!
################################################################################

-include ../makefile.init

RM := rm -rf
CP := cp -r
CHMOD := chmod

# All of the sources participating in the build are defined here
-include sources.mk
-include src/subdir.mk
-include subdir.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
endif

-include ../makefile.defs

# Add inputs and outputs from these tool invocations to the build variables 

# All Target
all: AvunaDNSD

debug: $(OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C Linker'
	$(CC) -DDEBUG -DSUPPORTS_MYSQL $(CFLAGS) -o "AvunaDNSD" $(OBJS) $(USER_OBJS) $(LIBS) -lmysqlclient
	@echo 'Finished building target: $@'
	@echo ' '

nomysql: $(OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C Linker'
	$(CC) $(CFLAGS) -o "AvunaDNSD" $(OBJS) $(USER_OBJS) $(LIBS)
	@echo 'Finished building target: $@'
	@echo ' '


# Tool invocations
AvunaDNSD: $(OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C Linker'
	$(CC) -DSUPPORTS_MYSQL $(CFLAGS) -o "AvunaDNSD" $(OBJS) $(USER_OBJS) $(LIBS) -lmysqlclient
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) $(EXECUTABLES)$(OBJS)$(C_DEPS) AvunaDNSD
	-@echo ' '

.PHONY: all clean dependents
.SECONDARY:

-include ../makefile.targets
