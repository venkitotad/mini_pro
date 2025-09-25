import User from "../Models/UserRegister.js";

// Register
export const registerUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Simple check
    if (!email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const user = new User({ email, password });
    await user.save();

    res.status(201).json({ message: "User registered successfully", user });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Login
export const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email, password });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    res.json({ message: "Login successful", user });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};
