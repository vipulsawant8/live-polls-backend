import z from "zod";

export const addPollSchema = z.object({
    title: z.string().trim().min(1, "Title is required"),
    options: z
    .array(
      z.object({
        text: z.string().trim().min(1, "Option text is required")
      })
    )
    .min(2, "At least 2 options are required")
    .max(6, "Maximum 6 options allowed")
});