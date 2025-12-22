# Palette's Journal

## 2024-05-22 - Subnet Auto-detection Feedback
**Learning:** CLI users often face a "hanging" cursor when tools perform initial environment checks (like network detection).
**Action:** Always wrap blocking "auto-detect" or setup phases in a visual spinner (`console.status`) to indicate activity and prevent "is it broken?" confusion.
