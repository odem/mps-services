# Makefile Setup
.PHONY: default all build up down restart exec purge
default:all
all: build up

# Makefile config
TARGETS := swag vpn portainer nextcloud mailu

define dojobs
  for t in $(TARGETS) ; do  make -C $$t/ $(1) ; done 
endef

# Compose targets
build:
	$(call dojobs,$@)
up: 
	$(call dojobs,$@)
down:
	$(call dojobs,$@)
restart:
	$(call dojobs,$@)
exec:
	$(call dojobs,$@)
purge:
	$(call dojobs,$@)
