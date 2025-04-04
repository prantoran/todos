mismatch_log.json schema
llm_log.json schema

size_mismatch
	ocr_count
	llm_count
missing_transactions
	count

metrics for process_mismatch_log = {
            'total_input': ocr_count,
            'dropped': dropped,
            'hallucinated': hallucinated,
            'llm_count': llm_count
        }
file name format:  page_2_chunk_0_llm_log.json


data from s3
{
input_transactions

}

llm log = {
            'input_transactions': input_transactions,
            'page': identifiers.get('page', 'unknown'),
            'chunk': identifiers.get('chunk', 'unknown'),
            'month': month
        }
In print_statistical_analysis_table()
	why std = 0 and cnt = 1 for overall

chunk data
	error_rate
		can errors be negative

what is audit LLM
input transaction counts?

page_chunk_key: month_page_chunk

llm_key = f"{month}_{page}_{chunk}"

monthly_metrics[month_key] = {
                    'total_input': 0,
                    'dropped': 0,
                    'hallucinated': 0,
                    'pages': set(),
                    'chunks': set()
                }


https://nostarch.com/pf3
https://mrjester.hapisan.com/04_MC68/
https://www.redhat.com/en/services/training/rh024-red-hat-linux-technical-overview?intcmp=701f20000012ngPAAQ&section=outline
https://alice.climent-pommeret.red/posts/a-syscall-journey-in-the-windows-kernel/
https://www.virusbulletin.com/
https://d3ext.github.io/page3/
https://unprotect.it/category/sandbox-evasion/
virtio-mmio vs virtio-pci
https://www.youtube.com/watch?v=p9fbofDUUr4
https://papers.freebsd.org/2019/eurobsdcon/shwartsman_gallatin-kernel_tls_harware_offload/
https://papers.freebsd.org/2024/bsdcan/norris_quiz/
performance and profiling: perf , bpftrace , fio , gdb , strace , blktrace .
block device construction: gdisk , dmsetup , cryptsetup , ...
OpenZFS test suite support: ksh , ...
Boot support: tini , udev , kmod
remote tmux
one-shot, diskless Linux VMs
intrd boot
netperf 
