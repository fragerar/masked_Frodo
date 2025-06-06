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


.macro nopnop
	nop
	nop
	nop
	nop
.endm

.macro clean_registers
	eor r4, r4, r4
	eor r5, r5, r5
	eor r6, r6, r6
	eor r7, r7, r7
	eor r8, r8, r8
	eor r9, r9, r9
	eor r10, r10, r10
	eor r11, r11, r11
	eor r12, r12, r12
	eor r14, r14, r14
.endm

.global asm_sec_and_u8
asm_sec_and_u8:

	push {r4-r11,r14}

	pz          .req r0
	py          .req r1
	px    			.req r2
	pool        .req r3
  t1          .req r4
	rx0         .req r5
	rx1         .req r6
	rz0		    	.req r7
	rz1			    .req r8
  t2          .req r9
	ry0			    .req r10
  ry1         .req r11
	r           .req r12



	ldrb rx0, [px], #1
	ldrb rx1, [px], #1
	ldrb ry0, [py], #1
	ldrb ry1, [py], #1
  ldrb r, [pool], #1

	secand rz0, rz1, rx0, rx1, ry0, ry1, t1, t2, r

	strb rz0, [pz], #1
	strb rz1, [pz], #1

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



.global asm_sec_and_u16
asm_sec_and_u16:

	push {r4-r11,r14}

	pz          .req r0
	py          .req r1
	px			    .req r2
	pool        .req r3
  t1          .req r4
	rx0         .req r5
	rx1         .req r12
	rz0			    .req r7
	rz1			    .req r8
  t2          .req r9
	ry0		    	.req r10
  ry1         .req r11
	r           .req r6


	ldrh rx0, [px], #2
	ldrh r, [pool]
	ldrh rx1, [px], #2
	nop

	ldrh ry0, [py], #2
	nop
  strh t1, [pool]	
  nop
	ldrh ry1, [py], #2
	nop


	and rz0, rx0, ry0
	eor t1, t1, t1
	and rz1, rx1, ry1


	eor px, px, px
	and t1, rx0, ry1


	eor px, px, px
	and t2, rx1, ry0

	nop
	eor px, px, px
	eor t1, r, t1



	eor t1, t2, t1

	eor px, px, px
	eor rz0, rz0, r

	nop
	eor px, px, px
	eor rz1, rz1, t1


	eor px, px, px
	nop
	strh rz0, [pz], #2
	nop
  strh px, [pool]
  nop
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


.global asm_convert_BA_u16
asm_convert_BA_u16:

	push {r4-r11,r14}

	px          .req r1
	py          .req r0
	pool		.req r2
	T	        .req r3
    rx0	        .req r4
	rx1         .req r5
	ry0         .req r6
	ry1   		.req r7
	G			.req r8
    t1         	.req r9
	t2			.req r10
    t3         	.req r11
	t4          .req r12

	ldrh G, [pool]
	ldrh rx1, [px, #2]

	eor	G, G, rx1
	strh rx1, [py, #2]
	eor rx1, t4, t4
	
	ldrh t1, [pool]
	ldrh rx0, [px]

	eor T, rx0, t1

	sub T, T, t1

	eor T, T, rx0 
	ldr t1,=0x0000ffff
	and T, T, t1 
	
	eor	ry0, rx0, G
	eor rx0, t4, t4
	sub ry0, ry0, G
	ldr t1,=0x0000ffff
	and ry0, ry0, t1

	eor t3,T, ry0

	strh t3, [py]

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



	.global asm_convert_AB_u16
asm_convert_AB_u16:

    push {r4-r11,r14}

    py          .req r0
    px          .req r1
    pool            .req r2
    T             .req r3
  rx0           .req r4
    rx1         .req r5
    ry0         .req r6
    ry1             .req r7
    G                 .req r8
  O           .req r9
    t1              .req r10
  t2          .req r11
    t3          .req r12


    ldrh rx0, [px], #2
    ldrh G, [pool], #2
    ldrh rx1, [px], #2

   
    lsl T, G, #1
    ldr t2,=0x0000ffff
    and T, T, t2
    eor t3, G, rx1



    nop
    nop
    nop
    nop

    and O, G, t3
    eor ry0, T, rx0
    and t2, T, rx0
    eor G, G, ry0

    eor t1, G, G
    
    and G, G, rx1

    eor t1, G, G
    
    eor O, O, G


    eor t1, T, T
    
    eor O, O, t2

    nop
    eor t2, t2, t2



    .rept 15
      eor t2, T, T
    	eor t3, rx1, rx1
      and G, T, rx1

      eor G, G, O
      and T, T, rx0
      eor G, G, T
      eor t1, t2, t2
      lsl T, G, #1
      ldr t2,=0x0000ffff
    	and T, T, t2
    .endr


     nop
     eor t3, t3, t3
     eor ry0, ry0, T

     nop
		 eor px, px, px
		 nop
     strh t2, [pool]
		 nop
     strh ry0, [py], #2
     nop
     strh t2, [pool]
     nop
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


.global asm_sec_add_u16
asm_sec_add_u16: 

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
	ldrh G, [pool]
	ldrh rx1, [px], #2
	nop


	eor	G, G, rx1
	ldrh O, [pool], #2


	nop
	eor px, px, px 
	eor T, rx0, O
	sub T, T, O


	eor T, T, rx0 
	ldr O,=0x0000ffff
	and T, T, O 



	eor	ry0, rx0, G
	sub ry0, ry0, G
	eor rx0, ry0, T
	ldr O,=0x0000ffff
	and ry0, ry0, O



	


	eor O, O, O
	nopnop
	
	ldrh ry0, [py], #2
	nop
  ldrh G, [pool]
  nop
	ldrh ry1, [py], #2
	nop


	eor	G, G, ry1

  ldrh py, [pool]

	nop
	eor px, px, px
	eor T, ry0, py
	sub T, T, py
	eor T, T, ry0 
	ldr O,=0x0000ffff
	and T, T, O 



	eor	rz0, ry0, G
	sub rz0, rz0, G
	eor ry0, rz0, T
	ldr O,=0x0000ffff
	and T, T, O 



  add rx0, rx0, ry0

  nop
  eor px,px,px

  add rx1, rx1, ry1
  strh rx1, [pz, #2]


	nop
  ldrh G, [pool], #2
  nop

	lsl T, G, #1
  ldr px,=0x0000ffff
  and T, T, px
	eor rz0, G, rx1

	nopnop


	and	O, G, rz0
	eor	rz0, T, rx0
	and	py, T, rx0
	eor	G, G, rz0


	eor px, px, px
	and	G, G, rx1

	eor px, px, px
	eor	O, O, G

	eor px, px, px
	eor	O, O, py

	nop
	eor px, px, px



	.rept 15
		eor px, px, px
		and G, T, rx1
		eor	G, G, O
		and T, T, rx0
		eor G, G, T
		eor px, px, px
		lsl T, G, #1
		ldr px,=0x0000ffff
  	and T, T, px

	.endr





  nop
  eor px, px, px
	eor rz0, rz0, T
    eor px, px, px


	nop
	strh rz0, [pz], #2

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





.global asm_sec_zero_test_bool_u16
asm_sec_zero_test_bool_u16:

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
  ldr t1, =#0xFFFF
	ldrh ra1, [pin], #2



	mvn rc0, ra0  
  and rc0, rc0, t1
  //orr rc0, rc0, #0x0000 // ~in[0]) | ((1<<(1<<logk))-(1<<k))
  nop
  eor pin, pin, pin 
  mov rc1, ra1		    // out[i] = in[i]
  nop
  eor pin, pin, pin 

  lsr rb0, rc0, #1		// z[j] = out[j] >> (1);
  nop
  eor pin, pin, pin
  lsr rb1, rc1, #1

  
  ldrh r, [pool], #2    // full_bool_refresh_u16(z, n)
  eor rb0, rb0, r
  nop
  eor pin, pin, pin
  eor rb1, rb1, r

 
  
  and ra0, rc0, rb0		// sec_and_u16(temp, z, out, n);
  eor pin, pin, pin
  and ra1, rc1, rb1

  eor pin, pin, pin
  ldrh r, [pool], #2

  eor pin, pin, pin
  and t1, rc0, rb1


  nop
	eor pin, pin, pin
  mov rc0, ra0
  eor t1, t1, r
  
  nop
  eor pin, pin, pin
  and t2, rc1, rb0 

  nop
  eor pin, pin, pin
  mov rc1, ra1 

  
  nop
  eor pin, pin, pin
  eor t1, t1, t2

  eor pin, pin, pin
  eor rc0, rc0, r

  nop
  eor pin, pin, pin
  eor rc1, rc1, t1


  nop
  eor pin, pin, pin
  lsr rb0, rc0, #2	    // z[j] = out[j] >> (2);
  nop
  eor pin, pin, pin
  lsr rb1, rc1, #2 

  nop
  eor pin, pin, pin
  

  ldrh r, [pool], #2    // full_bool_refresh_u16(z, n)
  eor rb0, rb0, r 
  nop
  eor pin, pin, pin
  eor rb1, rb1, r

 
  and ra0, rc0, rb0     // sec_and_u16(temp, z, out, n);
  eor pin, pin, pin
  and ra1, rc1, rb1

  eor pin, pin, pin
  and t1, rc0, rb1
  
  eor pin, pin, pin
  ldrh r, [pool], #2

  nop
  eor pin, pin, pin
  eor t1, t1, r

  nop
  eor pin, pin, pin
  and t2, rc1, rb0
  
  nop
  eor pin, pin, pin
  eor t1, t1, t2

  nop
  eor pin, pin, pin  
  eor rc0, ra0, r

  nop
  eor pin, pin, pin
  eor rc1, ra1, t1
  

  nop
  eor pin, pin, pin
  lsr rb0, rc0, #4		// z[j] = out[j] >> (4);
  
  nop
  eor pin, pin, pin
  lsr rb1, rc1, #4

  nop
  eor pin, pin, pin

  ldrh r, [pool], #2    // full_bool_refresh_u16(z, n)  

  eor rb0, rb0, r
  nop
  eor pin, pin, pin
  eor rb1, rb1, r
  

  nop
  eor pin, pin, pin
  and ra0, rc0, rb0     // sec_and_u16(temp, z, out, n)
  nop

  eor pin, pin, pin
  and ra1, rc1, rb1 
  
  nop
  eor pin, pin, pin
  and t1, rc0, rb1 

  nop
  eor pin, pin, pin 
  ldrh r, [pool], #2  

  nop
  eor pin, pin, pin
  eor t1, t1, r 

  nop
  eor pin, pin, pin
  and t2, rc1, rb0 

  nop
  eor pin, pin, pin 
  eor t1, t1, t2  

  nop
  eor pin, pin, pin
  eor rc0, ra0, r  

  nop
  eor pin, pin, pin
  eor rc1, ra1, t1
  






  nop
  eor pin, pin, pin
  lsr rb0, rc0, #8  	// z[j] = out[j] >> (8);


  nop
  eor pin, pin, pin
  lsr rb1, rc1, #8

  nop
  eor pin, pin, pin


  ldrh r, [pool], #2    // full_bool_refresh_u16(z, n)  
  eor rb0, rb0, r  

  nop
  eor pin, pin, pin
  eor rb1, rb1, r


  nop
  eor pin, pin, pin
  and ra0, rc0, rb0 	// sec_and_u16(temp, z, out, n);


  nop
  eor pin, pin, pin
  and ra1, rc1, rb1  

  nop
  eor pin, pin, pin
  ldrh r, [pool], #2 


  nop
  eor pin, pin, pin
  and t1, rc0, rb1 


  nop
  eor pin, pin, pin
  eor t1, t1, r 


  nop
  eor pin, pin, pin
  and t2, rc1, rb0 


  nop
  eor pin, pin, pin
  eor t1, t1, t2


  nop
  eor pin, pin, pin
  eor rc0, ra0, r


  nop
  eor pin, pin, pin
  eor rc1, ra1, t1







  
  nop
  eor pin, pin, pin
  and rc0, rc0, #1 		// out[i] = (out[i])&1;
  nop
  eor pin, pin, pin
  and rc1, rc1, #1
  nop
  eor pin, pin, pin
  

  ldrh r, [pool] 	// full_bool_refresh_u16(out, n);
  eor rc0, rc0, r
  nop
  eor pin, pin, pin 
  eor rc1, rc1, r
  
  ldr r, =#0xfff 
  and rc0, rc0, r
  nop
  eor pin, pin, pin
  and rc1, rc1, r
  

	nop
  strh rc0, [pout], #2
  nop 
  strh pin, [pool]
  nop
  strh rc1, [pout], #2 


	pop {r4-r11,pc}
	