	.text
	.globl	sort_tree
	.type	sort_tree, @function

# rdi: root
# rsi: i
# rdx: sorted_nums

sort_tree:
	pushq	%rbp
	movq	%rsp, %rbp
  # root: r8
  movq  %rdi, %r8
  # i: r9d
  movl  %esi, %r9d
  # sorted_nums: r10
  movq  %rdx, %r10
  # [+] if(root->left) i = sort_tree(root->left, i, sorted_nums)
  movq  8(%r8), %rcx
  testq %rcx, %rcx
  je    .no_left
  lea   8(%r8), %rdi
  movl  %r9d, %esi
  movq  %r10, %rdx
  call  sort_tree
  movl  %eax, %r9d
.no_left:
  # [+] sorted_nums[i] = root->data
  movl  (%r8), %ecx
  movl  %ecx, (%r10, %r9, 4)
  # [+] i = i + 1
  incl  %r9d
  # [+] if(root->right) i = sort_tree(root->right, i, sorted_nums)
  movq  16(%r8), %rcx
  testq %rcx, %rcx
  je    .no_right
  lea   16(%r8), %rdi
  movl  %r9d, %esi
  movq  %r10, %rdx
  call  sort_tree
  movl  %eax, %r9d
.no_right:
  # [+] return i
  movl  %r9d, %eax
	leave
	ret
	.size	sort_tree, .-sort_tree
	.section	.note.GNU-stack,"",@progbits
