export const resumeKey = "howl.resumeDeviceLink";

export function deviceName(device) {
  return device.name || "Device " + device.id.slice(0, 12);
}

export function fillIdentity(container, device) {
  container.querySelector(".device-id code").textContent = device.id;
  const groups = device.fingerprint.match(/.{1,8}/g).map(part => {
    const span = document.createElement("span");
    span.textContent = part;
    return span;
  });
  container.querySelector(".fingerprint code").replaceChildren(...groups);
}
