export type DeviceIdentity = { id: string; name?: string | null; fingerprint: string };

export function element<T extends HTMLElement = HTMLElement>(id: string): T {
  const node = document.getElementById(id);
  if (!node) throw new Error("Missing page element " + id + ".");
  return node as T;
}

export const resumeKey = "howl.resumeDeviceLink";

export function deviceName(device: DeviceIdentity) {
  return device.name || "Device " + device.id.slice(0, 12);
}

export function fillIdentity(container: Element, device: DeviceIdentity) {
  container.querySelector(".device-id code")!.textContent = device.id;
  const groups = (device.fingerprint.match(/.{1,8}/g) ?? []).map((part) => {
    const span = document.createElement("span");
    span.textContent = part;
    return span;
  });
  container.querySelector(".fingerprint code")!.replaceChildren(...groups);
}
