code_submission.zip: 
	cd prf-chunker/datasets && $(MAKE) clean
	rm -rf prf-chunker/target
	cd restic-chunker/datasets && $(MAKE) clean
	zip -r code_submission.zip prf-chunker restic-chunker README.md

clean:
	rm code_submission.zip

.PHONY: clean
