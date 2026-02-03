"use strict";

const particleCount = 1000; // Balanced for performance and quality
const particlePropCount = 11;
const particlePropsLength = particleCount * particlePropCount;
const spawnRadius = rand(150) + 150;
const noiseSteps = 6;
const { buffer, ctx } = createRenderingContext()

let center;
let tick;
let simplex;
let particleProps;
let isPaused = false;
let lastFrameTime = 0;
const fps = 60;
const frameInterval = 1000 / fps;
const dpr = window.devicePixelRatio || 1;

let canvasWidth, canvasHeight;
let mouse = { x: -1000, y: -1000, active: false };
let avoidRects = [];
let activeRipples = [];
let prevRipples = [];

function setup() {
	tick = 0;
	center = [];
	resize();
    updateAvoidRects();
	
	const savedTick = sessionStorage.getItem('aether_tick');
	const savedProps = sessionStorage.getItem('aether_props');
	
	if (savedTick && savedProps) {
		try {
			tick = parseInt(savedTick);
			const propsArray = JSON.parse(savedProps);
            if (propsArray.length !== particlePropsLength) throw new Error();
			particleProps = new Float32Array(propsArray);
			simplex = new SimplexNoise();
		} catch (e) {
			createParticles();
		}
	} else {
		createParticles();
	}
	
	lastFrameTime = performance.now();
	window.requestAnimationFrame(draw);
}

window.addEventListener("mousemove", e => {
    mouse.x = e.clientX;
    mouse.y = e.clientY;
    mouse.active = true;
});

window.addEventListener("touchstart", e => {
    mouse.x = e.touches[0].clientX;
    mouse.y = e.touches[0].clientY;
    mouse.active = true;
});

window.addEventListener("touchmove", e => {
    mouse.x = e.touches[0].clientX;
    mouse.y = e.touches[0].clientY;
    mouse.active = true;
});

window.addEventListener("touchend", () => {
    mouse.active = false;
});

window.addEventListener("mouseleave", () => {
    mouse.active = false;
});

window.addEventListener("pagehide", () => {
	try {
		sessionStorage.setItem('aether_tick', tick.toString());
		sessionStorage.setItem('aether_props', JSON.stringify(Array.from(particleProps)));
	} catch (e) {
		// Storage full or quota exceeded
	}
});

function createParticles() {
	simplex = new SimplexNoise();
	particleProps = new Float32Array(particlePropsLength);
	
	for (let i = 0; i < particlePropsLength; i += particlePropCount) {
		initParticle(i);
	}
}

function initParticle(i) {
    let x, y;
    let attempts = 0;
    const maxAttempts = 10;

    do {
        const rd = rand(spawnRadius) * 1.5;
        const rt = rand(TAU);
        const cx = cos(rt);
        const sy = sin(rt);
        x = center[0] + cx * rd;
        y = center[1] + sy * rd;
        attempts++;
    } while (isInAvoidRect(x, y) && attempts < maxAttempts);

	const rv = randIn(0.1, 1);
	const s = randIn(1, 8);
	const vx = rv * 0.1 * (x - center[0]) / spawnRadius; // Initial slight movement
	const vy = rv * 0.1 * (y - center[1]) / spawnRadius;
	const w = randIn(0.1, 2);
	const h = randIn(160, 260); 
	const l = 0;
	const ttl = randIn(50, 250);
	
	particleProps.set([x, y, vx, vy, s, h, w, l, ttl, 0, 0], i);
}

function updateAvoidRects() {
    avoidRects = [];
    const elements = document.querySelectorAll('.container, #loginContainer');
    elements.forEach(el => {
        const rect = el.getBoundingClientRect();
        avoidRects.push({
            x: rect.left,
            y: rect.top,
            width: rect.width,
            height: rect.height,
            cx: rect.left + rect.width / 2,
            cy: rect.top + rect.height / 2,
            radius: Math.max(rect.width, rect.height) / 2 * 1.2 
        });
    });
}

function isInAvoidRect(x, y) {
    for (let j = 0; j < avoidRects.length; j++) {
        const rect = avoidRects[j];
        if (x > rect.x - 20 && x < rect.x + rect.width + 20 &&
            y > rect.y - 20 && y < rect.y + rect.height + 20) {
            return true;
        }
    }
    return false;
}

function drawParticle(i) {
    // Access properties directly to avoid array creation/destructuring
    const x = particleProps[i];
    const y = particleProps[i + 1];
    let vx = particleProps[i + 2];
    let vy = particleProps[i + 3];
    const s = particleProps[i + 4];
    const w = particleProps[i + 6];
    let l = particleProps[i + 7];
    let ttl = particleProps[i + 8];
    let whiteState = particleProps[i + 9];
    let interactionType = particleProps[i + 10]; // 0:None, 1:Quantum, 2:Orbit, 3:Ripple
    
    const n = simplex.noise3D(x * 0.0025, y * 0.0025, tick * 0.0005) * TAU * noiseSteps;
    
    // Normal movement (if not fully consumed by white state logic)
    if (whiteState < 1 && interactionType !== 2) {
        vx = lerp(vx, cos(n), 0.05);
        vy = lerp(vy, sin(n), 0.05);
    }

    // Avoid login forms
    for (let j = 0; j < avoidRects.length; j++) {
        const rect = avoidRects[j];
        if (x > rect.x - 20 && x < rect.x + rect.width + 20 &&
            y > rect.y - 20 && y < rect.y + rect.height + 20) {
            const dx_r = x - rect.cx;
            const dy_r = y - rect.cy;
            const d_r = sqrt(dx_r * dx_r + dy_r * dy_r) || 1;
            const force = (rect.radius - d_r) / rect.radius;
            if (force > 0) {
                vx += (dx_r / d_r) * force * 0.8;
                vy += (dy_r / d_r) * force * 0.8;
            }
        }
    }

    // Ripple Repulsion (Shockwave)
    for (let j = 0; j < prevRipples.length; j++) {
        const r = prevRipples[j];
        const dx_r = x - r.x;
        const dy_r = y - r.y;
        const dist_r = sqrt(dx_r * dx_r + dy_r * dy_r);
        
        // Ring effect: only affect if near the expanding radius
        if (Math.abs(dist_r - r.radius) < 20) {
            const force = 5.0; // Strong impulse
            vx += (dx_r / dist_r) * force;
            vy += (dy_r / dist_r) * force;
        }
    }

    // Mouse influence
    if (mouse.active) {
        const dx_m = mouse.x - x;
        const dy_m = mouse.y - y;
        const d_m = sqrt(dx_m * dx_m + dy_m * dy_m);
        
        if (d_m < 40 && whiteState === 0 && interactionType === 0) {
            // Touch trigger
            whiteState = 0.01;
            const rand = Math.random();
            if (rand < 0.015) { // ~1.5% Ripple (300% less than 0.05)
                interactionType = 3; 
            } else if (rand < 0.5) {
                interactionType = 2; // Orbit
            } else {
                interactionType = 1; // Quantum
            }
        } else if (d_m < 500 && whiteState === 0) {
            // Flow through attraction
            if (d_m > 50) {
                const m_factor = (1 - d_m / 500) * 0.15;
                vx = lerp(vx, dx_m / d_m, m_factor);
                vy = lerp(vy, dy_m / d_m, m_factor);
            }
        }
    }

    // --- Interaction Behaviors ---

    // Type 1: Quantum Leap (Teleportation)
    if (interactionType === 1 && whiteState > 0) {
        whiteState = Math.min(whiteState + 0.05, 1);
        
        // Jitter / Glitch
        if (Math.random() < 0.1) {
            particleProps[i] = x + randIn(-50, 50); // Jump X
            particleProps[i + 1] = y + randIn(-50, 50); // Jump Y
        }
        
        // Fast fade
        ttl = l + 30;
    }
    // Type 2: Orbiting Satellite
    else if (interactionType === 2 && whiteState > 0) {
        whiteState = Math.min(whiteState + 0.05, 1);
        
        if (mouse.active) {
            // Orbit logic: maintain distance, increase angle
            const dx_m = x - mouse.x;
            const dy_m = y - mouse.y;
            let angle = Math.atan2(dy_m, dx_m);
            const dist = sqrt(dx_m*dx_m + dy_m*dy_m);
            
            // Tangential velocity
            angle += 0.1; // Orbital speed
            
            // Soft spring to ideal radius (60px)
            const idealRadius = 60;
            const newRadius = lerp(dist, idealRadius, 0.1);
            
            // Set position directly (overriding velocity)
            particleProps[i] = mouse.x + Math.cos(angle) * newRadius;
            particleProps[i + 1] = mouse.y + Math.sin(angle) * newRadius;
            
            ttl = l + 10; // Keep alive indefinitely while orbiting
        } else {
            // Break orbit: fling away
            const dx_c = x - center[0];
            const dy_c = y - center[1];
            const d_c = sqrt(dx_c * dx_c + dy_c * dy_c) || 1;
            vx = lerp(vx, (dx_c / d_c) * 5, 0.1);
            vy = lerp(vy, (dy_c / d_c) * 5, 0.1);
            interactionType = 1; // Degrade to normal fade
        }
    }
    // Type 3: Ripple (Shockwave)
    else if (interactionType === 3 && whiteState > 0) {
        // Explode
        activeRipples.push({x: x, y: y, radius: 10}); // Start radius
        l = ttl + 1; // Die immediately (invisible source)
    }

    const dx = x + vx * s;
    const dy = y + vy * s;
    let dl = fadeInOut(l, ttl);
    if (whiteState > 0) dl = lerp(dl, 1, whiteState);

    // Color logic
    let hue = lerp(690, 740, dl);
    let sat = 100;
    let light = 50;

    if (whiteState > 0) {
        if (interactionType === 1) { // Quantum: Yellow
            hue = 60; 
            light = 70;
        } else if (interactionType === 2) { // Orbit: Bright White/Cyan
            hue = 180;
            sat = 0;
            light = 100;
        }
    }

    const color = `hsla(${hue}, ${sat}%, ${light}%, ${dl})`;

    buffer.lineWidth = dl * w + 1;
    buffer.strokeStyle = color;
    buffer.beginPath();
    buffer.moveTo(x, y);
    buffer.lineTo(dx, dy);
    buffer.stroke();
    
    l++;
    particleProps[i] = dx;
    particleProps[i + 1] = dy;
    particleProps[i + 2] = vx;
    particleProps[i + 3] = vy;
    particleProps[i + 7] = l;
    particleProps[i + 9] = whiteState;
    particleProps[i + 10] = interactionType;

    (checkBounds(dx, dy) || l > ttl) && initParticle(i);
}

function checkBounds(x, y) {
	return(
		x > canvasWidth ||
		x < 0 ||
		y > canvasHeight ||
		y < 0
	);
}

function resize() {
	canvasWidth = window.innerWidth;
	canvasHeight = window.innerHeight;

	buffer.canvas.width = canvasWidth * dpr;
	buffer.canvas.height = canvasHeight * dpr;
	buffer.setTransform(dpr, 0, 0, dpr, 0, 0);

	ctx.canvas.width = canvasWidth * dpr;
	ctx.canvas.height = canvasHeight * dpr;
	ctx.canvas.style.width = canvasWidth + 'px';
	ctx.canvas.style.height = canvasHeight + 'px';
	ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

	center[0] = 0.5 * canvasWidth;
	center[1] = 0.5 * canvasHeight;
    updateAvoidRects();
}

function draw(currentTime) {
	if (isPaused) return;

	window.requestAnimationFrame(draw);

	const deltaTime = currentTime - lastFrameTime;
	if (deltaTime < frameInterval) return;

	lastFrameTime = currentTime - (deltaTime % frameInterval);

	tick++;
	
    // Manage Ripples
    prevRipples = activeRipples;
    activeRipples = [];
    for (let r of prevRipples) {
        if (r.radius < 600) { // Increased Max radius
            r.radius += 5; // Expansion speed
            activeRipples.push(r);
        }
    }

	buffer.clearRect(0, 0, canvasWidth, canvasHeight);
	
	ctx.fillStyle = 'black';
	ctx.fillRect(0, 0, canvasWidth, canvasHeight);
	
    // Draw Ripple Visuals
    ctx.save();
    ctx.lineWidth = 2;
    for (let r of activeRipples) {
        const opacity = 1 - (r.radius / 600);
        if (opacity > 0) {
            ctx.beginPath();
            ctx.strokeStyle = `rgba(100, 200, 255, ${opacity * 0.5})`;
            ctx.arc(r.x, r.y, r.radius, 0, TAU);
            ctx.stroke();
        }
    }
    ctx.restore();
	
	for (let i = 0; i < particlePropsLength; i += particlePropCount) {
		drawParticle(i);
	}
	
	// Apply glowing effect
	ctx.save();
	ctx.filter = 'blur(8px)';
	ctx.globalCompositeOperation = 'screen';
	ctx.drawImage(buffer.canvas, 0, 0, canvasWidth, canvasHeight);
	ctx.restore();
	
	// Sharp overlay
	ctx.save();
	ctx.globalCompositeOperation = 'lighter';
	ctx.drawImage(buffer.canvas, 0, 0, canvasWidth, canvasHeight);
	ctx.restore();
}

window.addEventListener("load", setup);
window.addEventListener("resize", debounce(resize, 150));