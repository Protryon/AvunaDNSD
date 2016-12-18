################################################################################
# Automatically-generated file. Do not edit!
################################################################################

-include ../makefile.init

RM := rm -rf
CP := cp -r
CHMOD := chmod
MKDIR := mkdir

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
all: mysql

debug: CFLAGS += -DDEBUG
debug: mysql

nomysql: AvunaDNSD

mysql: CFLAGS += -DSUPPORTS_MYSQL
mysql: LIBS += -lmysqlclient
mysql: AvunaDNSD

# Tool invocations
AvunaDNSD: $(OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C Linker'
	$(CC) $(CFLAGS) -o "AvunaDNSD" $(OBJS) $(USER_OBJS) $(LIBS)
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) $(EXECUTABLES)$(OBJS)$(C_DEPS) AvunaDNSD
	-@echo ' '

install: 
	-$(CP) AvunaDNSD /usr/bin/AvunaDNSD
	-$(CHMOD) 755 /usr/bin/AvunaDNSD
	-$(MKDIR) -p /etc/avuna/dnsd/
	-$(CP) ../master /etc/avuna/dnsd/master
	-$(CP) ../main.cfg /etc/avuna/dnsd/main.cfg


.PHONY: all clean dependents
.SECONDARY:

-include ../makefile.targets
