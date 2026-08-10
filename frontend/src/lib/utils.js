import { clsx } from "clsx";
import { twMerge } from "tailwind-merge";

/** shadcn/ui tarzı className birleştirme yardımcı fonksiyonu. */
export function cn(...inputs) {
  return twMerge(clsx(inputs));
}
