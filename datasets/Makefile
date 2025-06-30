datafiles = random_1M.bin random_4M.bin random_16M.bin random_64M.bin random_256M.bin random_1G.bin random_4G.bin random_16G.bin

$(datafiles):
	# 2^0, 2^2, 2^4, 2^6, 2^8, 2^10, 2^12, 2^14
	dd if=/dev/urandom of=random_1M.bin bs=1M count=1
	dd if=/dev/urandom of=random_4M.bin bs=1M count=4
	dd if=/dev/urandom of=random_16M.bin bs=1M count=16
	dd if=/dev/urandom of=random_64M.bin bs=1M count=64
	dd if=/dev/urandom of=random_256M.bin bs=1M count=256
	dd if=/dev/urandom of=random_1G.bin bs=1G count=1
	dd if=/dev/urandom of=random_4G.bin bs=1G count=4
	dd if=/dev/urandom of=random_16G.bin bs=1G count=16

clean:
	rm -f $(datafiles)
