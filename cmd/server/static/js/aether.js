"use strict";

const particleCount = 1000; // Balanced for performance and quality
const particlePropCount = 12;
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
let activeSonarRings = [];
let prevSonarRings = [];
let rippleCooldown = 0;
let meshNodes = [];

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
	
	particleProps.set([x, y, vx, vy, s, h, w, l, ttl, 0, 0, 0], i);
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
    const x = particleProps[i];
    const y = particleProps[i + 1];
    let vx = particleProps[i + 2];
    let vy = particleProps[i + 3];
    const s = particleProps[i + 4];
    const w = particleProps[i + 6];
    let l = particleProps[i + 7];
    let ttl = particleProps[i + 8];
    let whiteState = particleProps[i + 9];
    let interactionType = particleProps[i + 10];
    let rareEffect = particleProps[i + 11]; // 0:None, 1:Tension, 2:Prism, 3:Supercharge
    
    const n = simplex.noise3D(x * 0.0025, y * 0.0025, tick * 0.0005) * TAU * noiseSteps;
    
    // Base animation (noise)
    vx = lerp(vx, cos(n), 0.05);
    vy = lerp(vy, sin(n), 0.05);

    let sonarFlash = 0;
    // Check Sonar Hits (Flashing red dots)
    if (whiteState === 0) {
        for (let j = 0; j < prevSonarRings.length; j++) {
            const sr = prevSonarRings[j];
            const d_sr = sqrt((x-sr.x)**2 + (y-sr.y)**2);
            if (Math.abs(d_sr - sr.radius) < 15) {
                sonarFlash = 1;
                break;
            }
        }
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

    // Ripple Interaction
    for (let j = 0; j < prevRipples.length; j++) {
        const r = prevRipples[j];
        const dx_r = x - r.x;
        const dy_r = y - r.y;
        const dist_r = sqrt(dx_r * dx_r + dy_r * dy_r);
        if (r.age < 20) {
            if (dist_r < 200) {
                const force = 0.5;
                vx -= (dx_r / dist_r) * force;
                vy -= (dy_r / dist_r) * force;
            }
        } else {
            if (Math.abs(dist_r - r.radius) < 50) {
                const angle = Math.atan2(dy_r, dx_r);
                const hexAngle = Math.round(angle / (Math.PI / 3)) * (Math.PI / 3);
                const force = 8.0;
                vx += Math.cos(hexAngle) * force;
                vy += Math.sin(hexAngle) * force;
                particleProps[i+8] = l + 150; 
                if (whiteState === 0) { whiteState = 0.1; particleProps[i+9] = 0.1; }
            }
        }
    }

    // Mouse influence
    if (mouse.active) {
        const dx_m = mouse.x - x;
        const dy_m = mouse.y - y;
        const d_m = sqrt(dx_m * dx_m + dy_m * dy_m);
        
        if (d_m < 40 && whiteState === 0) {
            whiteState = 0.01;
            const rRoll = Math.random();
            
            // Interaction logic (Chances increased by 20%)
            if (rippleCooldown === 0 && rRoll < 0.000234) { 
                interactionType = 3; 
                rippleCooldown = 120; // Global cooldown
            } else if (rRoll < 0.000234 + 0.000280) { // Ultra Rare: Packet Sonar
                interactionType = 2;
                rareEffect = 4;
            } else if (Math.random() < 0.36) { // Mesh Node (Was Orbit)
                interactionType = 2; 
                const r = Math.random();
                if (r < 0.024) rareEffect = 3; // Supercharge
                else if (r < 0.06) rareEffect = 2; // Prism
            } else {
                interactionType = 1; // Quantum
            }
        } else if (d_m < 500 && whiteState === 0) {
            if (d_m > 50) {
                const m_factor = (1 - d_m / 500) * 0.15;
                vx = lerp(vx, dx_m / d_m, m_factor);
                vy = lerp(vy, dy_m / d_m, m_factor);
            }
        }
    }

    // Interaction Behaviors
    if (interactionType === 1 && whiteState > 0) {
        whiteState = Math.min(whiteState + 0.02, 1);
        
        // Quantum Leap: Random Teleportation
        if (Math.random() < 0.1) { 
            particleProps[i] += randIn(-50, 50); 
            particleProps[i + 1] += randIn(-50, 50); 
        }
        
        ttl = l + 150;
    }
    else if (interactionType === 2 && whiteState > 0) {
        whiteState = Math.min(whiteState + 0.05, 1);
        if (mouse.active) {
            const dx_m = mouse.x - x;
            const dy_m = mouse.y - y;
            const dist = sqrt(dx_m*dx_m + dy_m*dy_m);
            
            // Mesh Node Movement: Pull to mouse with organic jitter
            const pull = 0.15;
            vx = lerp(vx, dx_m / (dist || 1), pull) + randIn(-0.5, 0.5);
            vy = lerp(vy, dy_m / (dist || 1), pull) + randIn(-0.5, 0.5);
            
            ttl = l + 20;

            // Ultra Rare 4: Packet Sonar (Emit Ping)
            if (rareEffect === 4 && tick % 60 === 0) {
                activeSonarRings.push({x: x, y: y, radius: 0, max: 400});
            }
        } else {
            interactionType = 1;
        }
    }
    else if (interactionType === 0 && whiteState > 0) {
        whiteState = Math.min(whiteState + 0.02, 1);
    }
    else if (interactionType === 3 && whiteState > 0) {
        const baseAngle = Math.random() * Math.PI;
        activeRipples.push({x: x, y: y, radius: 100, age: 0, angle: baseAngle, vel: 0, delay: 0}); 
        activeRipples.push({x: x, y: y, radius: 60, age: 0, angle: baseAngle + 0.5, vel: 0, delay: 30}); 
        l = ttl + 1;
    }

    const dx = x + vx * s;
    const dy = y + vy * s;
    let dl = fadeInOut(l, ttl);
    if (whiteState > 0) dl = lerp(dl, 1, whiteState);

    let hue = lerp(690, 740, dl);
    let sat = 100;
    let light = 50;
    if (sonarFlash > 0) light = 90;

    if (whiteState > 0) {
        if (interactionType === 1) { 
            hue = lerp(hue, 780, whiteState); 
            light = lerp(50, 80, whiteState);
        } else if (interactionType === 2) { 
            if (rareEffect === 2) { // Prism: Cyan shift
                hue = 180; sat = 80; light = 70;
            } else if (rareEffect === 3) { // Supercharge: Intense white
                hue = 60; sat = 0; light = 100;
            } else {
                hue = 180; sat = 0; light = 100;
            }
        } else {
            sat = lerp(100, 0, whiteState);
            light = lerp(50, 100, whiteState);
        }
    }

    buffer.lineWidth = (dl * w + 1) * (rareEffect === 3 ? 3 : 1);
    buffer.strokeStyle = `hsla(${hue}, ${sat}%, ${light}%, ${dl})`;
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
    particleProps[i + 11] = rareEffect;

    if (interactionType === 2) {
        meshNodes.push({x: dx, y: dy, effect: rareEffect});
    }

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
	meshNodes = [];
	
    if (rippleCooldown > 0) rippleCooldown--;

    // Manage Sonar Rings
    prevSonarRings = activeSonarRings;
    activeSonarRings = [];
    for (let s of prevSonarRings) {
        if (s.radius < s.max) {
            s.radius += 8;
            activeSonarRings.push(s);
        }
    }

    // Manage Ripples
    prevRipples = activeRipples;
    activeRipples = [];
    for (let r of prevRipples) {
        if (r.delay > 0) {
            r.delay--;
            activeRipples.push(r);
            continue;
        }
        
        r.age++;
        if (r.age < 20) {
            // Implosion: Shrink radius, Spin Fast
            r.radius = lerp(r.radius, 0, 0.15);
            r.angle += 0.25;
            r.vel = 30; // Reduced initial velocity for smaller feel
            activeRipples.push(r);
        } else {
            // Explosion: Elastic physics (burst then slow)
            r.radius += r.vel;
            r.vel *= 0.94; // Friction
            r.angle += r.vel * 0.001; 
            if (r.radius < 800 && r.vel > 0.5) { // Reduced max radius to 800
                activeRipples.push(r);
            }
        }
    }

	buffer.clearRect(0, 0, canvasWidth, canvasHeight);
	
	ctx.fillStyle = 'black';
	ctx.fillRect(0, 0, canvasWidth, canvasHeight);
	
    // Draw Ripple Visuals (Advanced Liquid Hexagons)
    ctx.save();
    for (let r of activeRipples) {
        if (r.delay > 0) continue; // Don't draw yet

        let opacity = 0;
        let color = '';
        let isImplosion = r.age < 20;
        
        if (isImplosion) {
            opacity = r.age / 20;
            color = `rgba(100, 255, 255, ${opacity})`;
        } else {
            opacity = 1 - (r.radius / 800); // Adjusted for new max radius
            color = `rgba(255, 255, 200, ${opacity})`;
        }

        if (opacity > 0) {
            ctx.strokeStyle = color;
            ctx.lineWidth = isImplosion ? 2 : 3 * (1 - opacity); // Pulsating width
            
            drawAdvancedHexagon(ctx, r.x, r.y, r.radius, r.angle, r.age);

            // Draw Echo (Explosion only)
            if (!isImplosion) {
                ctx.strokeStyle = `rgba(255, 255, 200, ${opacity * 0.3})`;
                ctx.lineWidth = 1;
                drawAdvancedHexagon(ctx, r.x, r.y, r.radius * 0.9, r.angle - 0.05, r.age + 5);
            }
        }
    }
    ctx.restore();

    // Draw Sonar Rings
    ctx.save();
    for (let s of activeSonarRings) {
        const op = (1 - s.radius / s.max) * 0.3;
        if (op > 0) {
            ctx.beginPath();
            ctx.strokeStyle = `rgba(255, 255, 255, ${op})`;
            ctx.lineWidth = 1;
            ctx.arc(s.x, s.y, s.radius, 0, TAU);
            ctx.stroke();
        }
    }
    ctx.restore();
	
	for (let i = 0; i < particlePropsLength; i += particlePropCount) {
		drawParticle(i);
	}

    // Draw Neural Mesh Connections
    if (meshNodes.length > 1) {
        buffer.save();
        for (let i = 0; i < meshNodes.length; i++) {
            const n1 = meshNodes[i];
            for (let j = i + 1; j < meshNodes.length; j++) {
                const n2 = meshNodes[j];
                const d = sqrt((n1.x - n2.x) ** 2 + (n1.y - n2.y) ** 2);
                if (d < 45) {
                    const op = (1 - d / 45) * 0.5;
                    let hue = 180; // Default cyan/data mesh
                    if (n1.effect === 3 || n2.effect === 3) hue = 60; // Supercharge gold
                    buffer.strokeStyle = `hsla(${hue}, 100%, 70%, ${op})`;
                    buffer.lineWidth = 0.5;
                    buffer.beginPath();
                    buffer.moveTo(n1.x, n1.y);
                    buffer.lineTo(n2.x, n2.y);
                    buffer.stroke();
                }
            }
        }
        buffer.restore();
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

function drawAdvancedHexagon(ctx, x, y, r, angle, age) {
    const isExplosion = age >= 20;
    const segments = 6;
    const subDivisions = 12;
    
    for (let i = 0; i < segments; i++) {
        const thetaStart = angle + (Math.PI / 3) * i;
        const thetaEnd = angle + (Math.PI / 3) * (i + 1);
        
        // Never connected lines: add a gap between sides (15% gap)
        const margin = 0.15; 
        
        ctx.beginPath();
        let first = true;
        for (let j = 0; j <= subDivisions; j++) {
            // Digital Shatter: Random gaps during explosion
            if (isExplosion && Math.random() < 0.15) {
                first = true; // start new sub-path within segment
                continue;
            }

            const t = margin + (j / subDivisions) * (1 - 2 * margin);
            const subTheta = thetaStart + (thetaEnd - thetaStart) * t;
            
            // Liquid Edge: distortion via simplex noise
            const noise = simplex.noise2D(subTheta * 2, age * 0.1) * (isExplosion ? 25 : 5);
            const dist = r + noise;
            
            const px = x + dist * Math.cos(subTheta);
            const py = y + dist * Math.sin(subTheta);
            
            if (first) {
                ctx.moveTo(px, py);
                first = false;
            } else {
                ctx.lineTo(px, py);
            }
        }
        ctx.stroke();
    }
}

window.addEventListener("load", setup);
window.addEventListener("resize", debounce(resize, 150));