declare module "expo-notifications" {
  export function requestPermissionsAsync(): Promise<{ granted: boolean }>;
  export function getExpoPushTokenAsync(): Promise<{ data: string }>;
}
