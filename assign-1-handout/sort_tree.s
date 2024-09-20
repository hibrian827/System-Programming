	.text
	.globl	sort_tree
	.type	sort_tree, @function

# rdi: root
# rsi: i
# rdx: sorted_nums

sort_tree:
	pushq	%rbp
	movq	%rsp, %rbp
  subq  $0x10, %rsp
  # [+] if(root->left) i = sort_tree(root->left, i, sorted_nums)
  movq  8(%rdi), %rcx
  testq %rcx, %rcx
  je    .no_left
  movq  $1, %r8
  movq  %rdi, (%rsp, %r8, 8)
  decq  %r8
  movl  %esi, (%rsp, %r8, 8)
  movq  %rcx, %rdi
  call  sort_tree
  movq  $0, %r8
  movl  (%rsp, %r8, 8), %esi
  incq  %r8
  movq  (%rsp, %r8, 8), %rdi
  movl  %eax, %esi
.no_left:
  # [+] sorted_nums[i] = root->data
  movl  (%rdi), %ecx
  movl  %ecx, (%rdx, %rsi, 4)
  # [+] i = i + 1
  incl  %esi
  # [+] if(root->right) i = sort_tree(root->right, i, sorted_nums)
  movq  16(%rdi), %rcx
  testq %rcx, %rcx
  je    .no_right
  movq  $1, %r8
  movq  %rdi, (%rsp, %r8, 8)
  decq  %r8
  movl  %esi, (%rsp, %r8, 8)
  movq  %rcx, %rdi
  call  sort_tree
  movq  $0, %r8
  movl  (%rsp, %r8, 8), %esi
  incq  %r8
  movq  (%rsp, %r8, 8), %rdi
  movl  %eax, %esi
.no_right:
  # [+] return i
  movl  %esi, %eax
	leave
	ret
	.size	sort_tree, .-sort_tree
	.section	.note.GNU-stack,"",@progbits
