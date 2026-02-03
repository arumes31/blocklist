"use strict";

const particleCount = 1500; // Slightly reduced for performance
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
	let rd, rt, cx, sy, x, y, s, rv, vx, vy, w, h, l, ttl;
	
	rd = rand(spawnRadius) * 1.5;
	rt = rand(TAU);
	cx = cos(rt);
	sy = sin(rt);
	x = center[0] + cx * rd;
	y = center[1] + sy * rd;
	rv = randIn(0.1, 1);
	s = randIn(1, 8);
	vx = rv * cx * 0.1;
	vy = rv * sy * 0.1;
	w = randIn(0.1, 2);
	h = randIn(160, 260); // Not currently used but keeping for props structure
	l = 0;
	ttl = randIn(50, 200);
	
	particleProps.set([x, y, vx, vy, s, h, w, l, ttl], i);
}

function drawParticle(i) {
    let n, dx, dy, dl, c;
    const [x, y, vx, vy, s, h, w, l, ttl] = particleProps.get(i, particlePropCount);
    
    n = simplex.noise3D(x * 0.0025, y * 0.0025, tick * 0.0005) * TAU * noiseSteps;
    const nvx = lerp(vx, cos(n), 0.05);
    const nvy = lerp(vy, sin(n), 0.05);
    dx = x + nvx * s;
    dy = y + nvy * s;
    dl = fadeInOut(l, ttl);
    const hue = lerp(690, 740, dl);
    c = `hsla(${hue}, 100%, 50%, ${dl})`;

    buffer.lineWidth = dl * w + 1;
    buffer.strokeStyle = c;
    buffer.beginPath();
    buffer.moveTo(x, y);
    buffer.lineTo(dx, dy);
    buffer.stroke();
    
    const nextL = l + 1;
    particleProps.set([dx, dy, nvx, nvy, s, h, w, nextL, ttl], i);

    (checkBounds(dx, dy) || nextL > ttl) && initParticle(i);
}

function checkBounds(x, y) {
	return(
		x > buffer.canvas.width / dpr ||
		x < 0 ||
		y > buffer.canvas.height / dpr ||
		y < 0
	);
}

function resize() {
	const w = window.innerWidth;
	const h = window.innerHeight;

	buffer.canvas.width = w * dpr;
	buffer.canvas.height = h * dpr;
	buffer.setTransform(dpr, 0, 0, dpr, 0, 0);

	ctx.canvas.width = w * dpr;
	ctx.canvas.height = h * dpr;
	ctx.canvas.style.width = w + 'px';
	ctx.canvas.style.height = h + 'px';
	ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

	center[0] = 0.5 * w;
	center[1] = 0.5 * h;
}

function draw(currentTime) {
	if (isPaused) return;

	window.requestAnimationFrame(draw);

	const deltaTime = currentTime - lastFrameTime;
	if (deltaTime < frameInterval) return;

	lastFrameTime = currentTime - (deltaTime % frameInterval);

	tick++;
	
	// Clear buffer (offscreen)
	buffer.clearRect(0, 0, buffer.canvas.width / dpr, buffer.canvas.height / dpr);
	
	// Clear main ctx
	ctx.fillStyle = 'black';
	ctx.fillRect(0, 0, ctx.canvas.width / dpr, ctx.canvas.height / dpr);
	
	for (let i = 0; i < particlePropsLength; i += particlePropCount) {
		drawParticle(i);
	}
	
	// Apply glowing effect
	ctx.save();
	ctx.filter = 'blur(8px)';
	ctx.globalCompositeOperation = 'screen';
	ctx.drawImage(buffer.canvas, 0, 0, ctx.canvas.width / dpr, ctx.canvas.height / dpr);
	ctx.restore();
	
	// Sharp overlay
	ctx.save();
	ctx.globalCompositeOperation = 'lighter';
	ctx.drawImage(buffer.canvas, 0, 0, ctx.canvas.width / dpr, ctx.canvas.height / dpr);
	ctx.restore();
}

window.addEventListener("load", setup);
window.addEventListener("resize", debounce(resize, 150));