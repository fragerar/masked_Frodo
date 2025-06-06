.section .text
.syntax unified
.cpu cortex-m4
.thumb


.macro secand z0, z1, x0, x1, y0, y1, t1, t2, r
	and \z0, \x0, \y0
	and \z1, \x1, \y1

	and \t1, \x0, \y1
	and \t2, \x1, \y0
	eor \t1, \r, \t1
	eor \t1, \t2, \t1
	eor \z0, \z0, \r
	eor \z1, \z1, \t1
.endm


.global naive_asm_sec_and_u16
naive_asm_sec_and_u16:

	push {r4-r11,r14}

	pz          .req r0
	py          .req r1
	px			    .req r2
	pool        .req r3
  t1          .req r4
	rx0         .req r5
	rx1         .req r6
	rz0			    .req r7
	rz1			    .req r8
  t2          .req r9
	ry0		    	.req r10
  ry1         .req r11
	r           .req r12



	ldrh rx0, [px], #2
	ldrh rx1, [px], #2
	ldrh ry0, [py], #2
	ldrh ry1, [py], #2
  ldrh r, [pool], #2

	secand rz0, rz1, rx0, rx1, ry0, ry1, t1, t2, r

	strh rz0, [pz], #2
	strh rz1, [pz], #2

	.unreq pz          
	.unreq py          
	.unreq px			
	.unreq pool        
  .unreq t1          
	.unreq rx0         
	.unreq rx1         
	.unreq rz0			
	.unreq rz1			
  .unreq t2          
	.unreq ry0			
  .unreq ry1         
	.unreq r           

	pop {r4-r11,pc}


.global naive_asm_convert_BA_u16
naive_asm_convert_BA_u16:

	push {r4-r11,r14}

	py          .req r0
	px          .req r1
	pool		    .req r2
	T	          .req r3
  rx0	        .req r4
	rx1         .req r5
	ry0         .req r6
	ry1   			.req r7
	G			      .req r8
  t1          .req r9
	t2			    .req r10
  t3          .req r11
	t4          .req r12


	ldrh rx0, [px], #2
	ldrh rx1, [px], #2
  ldrh G, [pool], #2

	eor T, rx0, G
	sub T, T, G
	eor T, T, rx0 
	eor	G, G, rx1
	eor	ry0, rx0, G
	sub ry0, ry0, G
	eor ry0, ry0, T

	strh ry0, [py], #2
	strh rx1, [py], #2



	.unreq py          
	.unreq px          
	.unreq pool	
	.unreq T	       
  .unreq rx0	        
	.unreq rx1         
	.unreq ry0         
	.unreq ry1			
	.unreq G			
  .unreq t1          
	.unreq t2			
  .unreq t3          
	.unreq t4          

	pop {r4-r11,pc}



.global naive_asm_convert_AB_u16
naive_asm_convert_AB_u16:

	push {r4-r11,r14}

	py          .req r0
	px          .req r1
	pool    		.req r2
	T	          .req r3
  rx0	        .req r4
	rx1         .req r5
	ry0         .req r6
	ry1			    .req r7
	G			      .req r8
  O           .req r9
	t1			    .req r10
  t2          .req r11
	t3          .req r12


	ldrh rx0, [px], #2
	ldrh rx1, [px], #2
  ldrh G, [pool], #2

	lsl T, G, #1
	eor ry0, G, rx1
	and	O, G, ry0
	eor	ry0, T, rx0
	eor	G, G, ry0
	and	G, G, rx1
	eor	O, O, G
	and	G, T, rx0
	eor	O, O, G

	.rept 15

		and G, T, rx1
		eor	G, G, O
		and T, T, rx0
		eor G, G, T
		lsl T, G, #1

	.endr

	eor ry0, ry0, T

	strh ry0, [py], #2
	strh rx1, [py], #2

	.unreq py
	.unreq px
	.unreq pool
	.unreq T	
  .unreq rx0	
	.unreq rx1 
	.unreq ry0 
	.unreq ry1	
	.unreq G	
  .unreq O   
	.unreq t1	
  .unreq t2  
	.unreq t3  


	pop {r4-r11,pc}


.global naive_asm_sec_add_u16
naive_asm_sec_add_u16: 

	push {r4-r11,r14}

	pz          .req r0
	px          .req r1
	py  		    .req r2
	pool	      .req r3
  rx0	        .req r4
	rx1         .req r5
	ry0         .req r6
	ry1   			.req r7
	rz0		      .req r8
  rz1         .req r9
	G		  	    .req r10
  O           .req r11
	T           .req r12


	ldrh rx0, [px], #2
	ldrh rx1, [px], #2
  ldrh G, [pool], #2

	eor T, rx0, G
	sub T, T, G
	eor T, T, rx0 
	eor	G, G, rx1
	eor	ry0, rx0, G
	sub ry0, ry0, G
	eor rx0, ry0, T


	ldrh ry0, [py], #2
	ldrh ry1, [py], #2
  ldrh G, [pool], #2

	eor T, ry0, G
	sub T, T, G
	eor T, T, ry0 
	eor	G, G, ry1
	eor	rz0, ry0, G
	sub rz0, rz0, G
	eor ry0, rz0, T

  add rx0, rx0, ry0
  add rx1, rx1, ry1


  ldrh G, [pool], #2

	lsl T, G, #1
	eor rz0, G, rx1
	and	O, G, rz0
	eor	rz0, T, rx0
	eor	G, G, rz0
	and	G, G, rx1
	eor	O, O, G
	and	G, T, rx0
	eor	O, O, G

	.rept 15

		and G, T, rx1
		eor	G, G, O
		and T, T, rx0
		eor G, G, T
		lsl T, G, #1

	.endr

	eor rz0, rz0, T

	strh rz0, [pz], #2
	strh rx1, [pz], #2
  



	.unreq py          
	.unreq px          
	.unreq pool	
	.unreq T	       
  .unreq rx0	        
	.unreq rx1         
	.unreq ry0         
	.unreq ry1			
	.unreq G			
  .unreq pz          
	.unreq O			
  .unreq rz0          
	.unreq rz1          

	pop {r4-r11,pc}





.global naive_asm_sec_zero_test_bool_u16
naive_asm_sec_zero_test_bool_u16:

	push {r4-r11,r14}

	pout        .req r0
	pin         .req r1
	pool        .req r2
	t2          .req r3
	t3          .req r4
	ra0         .req r5
	ra1         .req r6
	rb0         .req r7
	rb1         .req r8
	rc0         .req r9
	rc1         .req r10
	t1          .req r11
	r           .req r12


	ldrh ra0, [pin], #2
	ldrh ra1, [pin], #2

  ldr t1, =#0xFFFF


  mvn rc0, ra0  
  and rc0, rc0, t1
  //orr rc0, rc0, #0x0000 // ~in[0]) | ((1<<(1<<logk))-(1<<k))
  mov rc1, ra1		    // out[i] = in[i]
  
  lsr rb0, rc0, #1		// z[j] = out[j] >> (1);
  lsr rb1, rc1, #1
  
  ldrh r, [pool], #2    // full_bool_refresh_u16(z, n)
  eor rb0, rb0, r
  eor rb1, rb1, r
  
  and ra0, rc0, rb0		// sec_and_u16(temp, z, out, n);
  and ra1, rc1, rb1
  ldrh r, [pool], #2
  and t1, rc0, rb1
  mov rc0, ra0
  eor t1, t1, r
  and t2, rc1, rb0 
  mov rc1, ra1 
  eor t1, t1, t2
  eor rc0, rc0, r
  eor rc1, rc1, t1

  lsr rb0, rc0, #2	    // z[j] = out[j] >> (2);
  lsr rb1, rc1, #2 

  ldrh r, [pool], #2    // full_bool_refresh_u16(z, n)
  eor rb0, rb0, r 
  eor rb1, rb1, r
  
  and ra0, rc0, rb0     // sec_and_u16(temp, z, out, n);
  and ra1, rc1, rb1
  and t1, rc0, rb1
  ldrh r, [pool], #2
  eor t1, t1, r
  and t2, rc1, rb0
  eor t1, t1, t2
  eor rc0, ra0, r
  eor rc1, ra1, t1
  

  lsr rb0, rc0, #4		// z[j] = out[j] >> (4);
  lsr rb1, rc1, #4

  ldrh r, [pool], #2    // full_bool_refresh_u16(z, n)  
  eor rb0, rb0, r
  eor rb1, rb1, r
  

  and ra0, rc0, rb0     // sec_and_u16(temp, z, out, n)
  and ra1, rc1, rb1 
  and t1, rc0, rb1  
  ldrh r, [pool], #2  
  eor t1, t1, r 
  and t2, rc1, rb0  
  eor t1, t1, t2  
  eor rc0, ra0, r  
  eor rc1, ra1, t1
  

  lsr rb0, rc0, #8  	// z[j] = out[j] >> (8);
  lsr rb1, rc1, #8

  ldrh r, [pool], #2    // full_bool_refresh_u16(z, n)  
  eor rb0, rb0, r  
  eor rb1, rb1, r
  
  and ra0, rc0, rb0 	// sec_and_u16(temp, z, out, n);
  and ra1, rc1, rb1  
  ldrh r, [pool], #2 
  and t1, rc0, rb1 
  eor t1, t1, r 
  and t2, rc1, rb0 
  eor t1, t1, t2
  eor rc0, ra0, r
  eor rc1, ra1, t1
  

  and rc0, rc0, #1 		// out[i] = (out[i])&1;
  and rc1, rc1, #1
  

  ldrh r, [pool], #2	// full_bool_refresh_u16(out, n);
  eor rc0, rc0, r 
  eor rc1, rc1, r
  
  ldr r, =#0xfff 
  and rc0, rc0, r
  and rc1, rc1, r
  

  strh rc0, [pout], #2 
  strh rc1, [pout], #2
  


	pop {r4-r11,pc}

	
	