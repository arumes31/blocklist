"use strict";

const particleCount = 1000; // Balanced for performance and quality
const particlePropCount = 9;
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

function setup() {
	tick = 0;
	center = [];
	resize();
	
	const savedTick = sessionStorage.getItem('aether_tick');
	const savedProps = sessionStorage.getItem('aether_props');
	
	if (savedTick && savedProps) {
		try {
			tick = parseInt(savedTick);
			const propsArray = JSON.parse(savedProps);
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
	const rd = rand(spawnRadius) * 1.5;
	const rt = rand(TAU);
	const cx = cos(rt);
	const sy = sin(rt);
	const x = center[0] + cx * rd;
	const y = center[1] + sy * rd;
	const rv = randIn(0.1, 1);
	const s = randIn(1, 8);
	const vx = rv * cx * 0.1;
	const vy = rv * sy * 0.1;
	const w = randIn(0.1, 2);
	const h = randIn(160, 260); 
	const l = 0;
	const ttl = randIn(50, 250);
	
	particleProps.set([x, y, vx, vy, s, h, w, l, ttl], i);
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
    const ttl = particleProps[i + 8];
    
    const n = simplex.noise3D(x * 0.0025, y * 0.0025, tick * 0.0005) * TAU * noiseSteps;
    vx = lerp(vx, cos(n), 0.05);
    vy = lerp(vy, sin(n), 0.05);

    // Mouse influence
    if (mouse.active) {
        const dx_m = mouse.x - x;
        const dy_m = mouse.y - y;
        const d_m = sqrt(dx_m * dx_m + dy_m * dy_m);
        if (d_m < 350) {
            const m_factor = (1 - d_m / 350) * 0.15;
            if (d_m > 0.1) {
                vx = lerp(vx, dx_m / d_m, m_factor);
                vy = lerp(vy, dy_m / d_m, m_factor);
            }
        }
    }

    const dx = x + vx * s;
    const dy = y + vy * s;
    const dl = fadeInOut(l, ttl);
    const hue = lerp(690, 740, dl);
    const color = `hsla(${hue}, 100%, 50%, ${dl})`;

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
}

function draw(currentTime) {
	if (isPaused) return;

	window.requestAnimationFrame(draw);

	const deltaTime = currentTime - lastFrameTime;
	if (deltaTime < frameInterval) return;

	lastFrameTime = currentTime - (deltaTime % frameInterval);

	tick++;
	
	buffer.clearRect(0, 0, canvasWidth, canvasHeight);
	
	ctx.fillStyle = 'black';
	ctx.fillRect(0, 0, canvasWidth, canvasHeight);
	
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