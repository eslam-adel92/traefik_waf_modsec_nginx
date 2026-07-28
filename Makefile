COMPOSE ?= docker compose
HOST    ?= $(shell grep -E '^APP_DOMAIN=' .env 2>/dev/null | cut -d= -f2 || echo whoami.localhost)

.PHONY: help up down restart logs waf-logs ps reload test versions pull update demo triggered

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

up: ## Start the gateway
	$(COMPOSE) up -d

demo: ## Start the gateway plus the demo backend
	$(COMPOSE) --profile demo up -d

down: ## Stop everything
	$(COMPOSE) --profile demo down

restart: ## Recreate containers (applies compose/.env changes)
	$(COMPOSE) up -d --force-recreate

reload: ## Reload WAF rules after editing modsec/custom-rules.conf
	$(COMPOSE) restart modsecurity

ps: ## Show container status
	$(COMPOSE) ps

logs: ## Tail Traefik logs
	$(COMPOSE) logs -f traefik

waf-logs: ## Tail WAF decisions (JSON audit log)
	$(COMPOSE) logs -f modsecurity

triggered: ## Rank the CRS rules that fired most (start here when tuning)
	@$(COMPOSE) logs modsecurity 2>/dev/null | grep -o '"ruleId":[0-9]*' | \
	  sort | uniq -c | sort -rn | head -20

versions: ## Show pinned vs latest upstream versions
	@./scripts/check-versions.sh

pull: ## Pull updated images for the pinned tags
	$(COMPOSE) --profile demo pull

update: pull restart ## Pull and recreate

test: ## Run the WAF smoke tests against $(HOST)
	@./scripts/smoke-test.sh $(HOST)
