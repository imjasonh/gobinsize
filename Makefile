svg/%:
	go run ./ -svg treemaps/$*.svg $(shell which $*)

.PHONY: svg
svg: svg/cosign svg/kubectl svg/gobinsize svg/chainctl
