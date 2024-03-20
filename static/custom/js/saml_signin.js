import * as THREE from "three";
import { GLTFLoader } from 'three/addons/loaders/GLTFLoader.js'
import { OrbitControls } from "three/addons/controls/OrbitControls.js";


const canvas = document.getElementById('canvas');
const scene = new THREE.Scene();
let mixer;
let clock = new THREE.Clock();
const actions = [];
const loader = new GLTFLoader();
// const url = "/static/3D_model/low_poly_humanoid_robot.glb";
// const url = "/static/3D_model/retro_computer_setup_free.glb";
const url = "/static/3D_model/apple_macpro_low_poly.glb";
let model = null;

loader.load(
    url,
    function (gltf) {
        model = gltf.scene;
        model.position.set(0, -0.5, 0);
        scene.add(model);

        mixer = new THREE.AnimationMixer(model);
        gltf.animations.forEach((animation) => {
            actions.push(mixer.clipAction(animation).play());
        });

        tick();
    },
    function (error) {
        console.log("An error happened");
        console.log(error);
    }
);

const pointLight = new THREE.PointLight(0xffffff, 0.1);
pointLight.position.x = 2;
pointLight.position.y = 3;
pointLight.position.z = 4;
scene.add(pointLight);

const pointLight2 = new THREE.PointLight(0xffffff, 2);
pointLight2.position.set(-1.86, 1, -1.65);
pointLight2.intensity = 7;

scene.add(pointLight2);

const pointLight3 = new THREE.PointLight(0xe1ff, 2);
pointLight3.position.set(2.13, -3, -1.98);
pointLight3.intensity = 6.8;

scene.add(pointLight3);

const sizes = {
    width: window.innerWidth,
    height: window.innerHeight,
};

window.addEventListener("resize", () => {
    sizes.width = window.innerWidth;
    sizes.height = window.innerHeight;

    camera.aspect = sizes.width / sizes.height;
    camera.updateProjectionMatrix();

    renderer.setSize(sizes.width, sizes.height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
});

const camera = new THREE.PerspectiveCamera(
    75,
    sizes.width / sizes.height,
    0.1,
    100
);
camera.position.x = 0;
camera.position.y = 0;
camera.position.z = 2;
scene.add(camera);

const controls = new OrbitControls(camera, canvas);
controls.enableDamping = true;

const renderer = new THREE.WebGLRenderer({
    canvas: canvas,
    alpha: true,
    antialias: true,
});
renderer.setSize(sizes.width, sizes.height);
renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

const tick = () => {
    const delta = clock.getDelta();
    mixer.update(delta);
    controls.update();
    renderer.render(scene, camera);

    window.requestAnimationFrame(tick);
};
