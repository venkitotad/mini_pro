import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card } from "@/components/ui/card"
import { Label } from "@/components/ui/label"

export default function RegisterPage() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
      <Card className="flex w-full max-w-4xl shadow-lg overflow-hidden">
        {/* Left Side - Register Form */}
        <div className="w-1/2 p-10 bg-white">
          <h2 className="text-3xl font-bold mb-6">Signup</h2>

          <form className="space-y-4">
            <div>
              <Label htmlFor="name">Full Name</Label>
              <Input id="name" placeholder="John Doe" />
            </div>
            <div>
              <Label htmlFor="email">Email</Label>
              <Input id="email" type="email" placeholder="you@example.com" />
            </div>
            <div>
              <Label htmlFor="password">Password</Label>
              <Input id="password" type="password" placeholder="********" />
            </div>
            <div>
              <Label htmlFor="confirmPassword">Confirm Password</Label>
              <Input id="confirmPassword" type="password" placeholder="********" />
            </div>

            <Button className="w-full">Signup</Button>
          </form>

          <div className="my-6 flex items-center justify-center text-sm text-gray-500">
            <span className="px-2">or signup with</span>
          </div>

          <div className="flex justify-center space-x-4">
            <Button variant="outline" size="icon">
              <i className="fab fa-facebook-f" />
            </Button>
            <Button variant="outline" size="icon">
              <i className="fab fa-google" />
            </Button>
            <Button variant="outline" size="icon">
              <i className="fab fa-linkedin-in" />
            </Button>
          </div>
        </div>

        {/* Right Side - Welcome message */}
        <div className="w-1/2 bg-gradient-to-br from-green-500 to-emerald-600 text-white flex flex-col items-center justify-center p-10">
          <h2 className="text-3xl font-bold mb-4">Welcome!</h2>
          <p className="text-center mb-6">
            Create your account and join us today. It only takes a minute to get started!
          </p>
          <Button variant="secondary" className="bg-white text-green-600 hover:bg-gray-100">
            Already have an account? Signin.
          </Button>
        </div>
      </Card>
    </div>
  )
}
