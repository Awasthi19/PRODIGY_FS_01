"use client";
import React,{useEffect, useState} from 'react'
import { useRouter } from 'next/navigation'
import Image from 'next/image'
import Link from 'next/link'
import axios from 'axios'
import { toast, ToastContainer } from 'react-toastify'
import 'react-toastify/dist/ReactToastify.css'


function Login() {
  const router = useRouter()

  const [user, setUser] = useState({
    username: '',
    email: '',
    password: ''
  })

  const [buttonDisabled, setButtonDisabled] = useState(true)
  useEffect(() => {
    if(user.email !== '' && user.password !== '') {
      setButtonDisabled(false)
    } else {
      setButtonDisabled(true)
    }
  }, [user])

  const [loading, setLoading] = useState(false)

  const handleChanges = (e: React.ChangeEvent<HTMLInputElement>) => {
    setUser({...user, [e.target.name]: e.target.value})
  }

  const handleSubmit = async (e:React.MouseEvent<HTMLButtonElement>) => {
    e.preventDefault()
    toast.info('Logging in...')
    try {
      setLoading(true)
      console.log(user)
      const username= "Rupchitran"

      
      const formData = new FormData()
      formData.append('username', username)
      formData.append('email', user.email)
      formData.append('password', user.password)
      const response = await axios.post(process.env.NEXT_PUBLIC_LOGIN_URL!, formData)
      if (response.data.jwt) {
        document.cookie = `jwt=${response.data.jwt}; path=/; secure; SameSite=None;`
        console.log(response.data.jwt)
        toast.success('Login successful')
        router.push('/profile')
      }
      else {
        console.log('Login failed')
        toast.error('Login failed')
      }
    } catch (error:any) {
      console.log(error.message)
      toast.error(error.message)
      
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <div className="flex min-h-full flex-1 flex-col justify-center px-6 py-12 lg:px-8">
        <div className="sm:mx-auto sm:w-full sm:max-w-sm flex flex-col gap-2 items-center ">
          <Image
            priority={true}
            width={200}
            height={200}
            src="/Logo.png"
            alt="Logo"
          />
          <h2 className=" text-center text-2xl font-bold leading-9 tracking-tight text-yellow-600">
            {loading ? "Loading...":"Login to your account"}
          </h2>
        </div>

        <div className="mt-10 sm:mx-auto sm:w-full sm:max-w-sm">
          <form className="space-y-6" action="#" method="POST">
            <div>
              <label htmlFor="email" className="block text-sm font-medium leading-6 text-white">
                Email address
              </label>
              <div className="mt-2">
                <input
                  id="email"
                  name="email"
                  type="email"
                  autoComplete="email"
                  required
                  className="bg-gray-300 block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                  value={user.email}
                  onChange={handleChanges}
                />
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between">
                <label htmlFor="password" className="block text-sm font-medium leading-6 text-white">
                  Password
                </label>
                <div className="text-sm">
                  <a href="#" className="font-semibold text-indigo-600 hover:text-indigo-500">
                    Forgot password?
                  </a>
                </div>
              </div>
              <div className="mt-2">
                <input
                  id="password"
                  name="password"
                  type="password"
                  autoComplete="current-password"
                  required
                  className="bg-gray-300 block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                  value={user.password}
                  onChange={handleChanges}
                />
              </div>
            </div>

            <div>
              <button
                type="submit"
                disabled={buttonDisabled}
                className={`${buttonDisabled?'bg-gray-600':'bg-yellow-600'} flex w-full justify-center rounded-md  px-3 py-1.5 text-sm font-semibold leading-6 text-white shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600`}
                onClick={handleSubmit}
              >
                Login
              </button>
            </div>
          </form>

          <p className="mt-10 text-center text-sm text-gray-500">
            Not a member?{' '}
            <Link href="#" className="font-semibold leading-6 text-indigo-600 hover:text-indigo-500">
              Register
            </Link>
          </p>
        </div>
      </div>
      <ToastContainer />
    </div>
  )
}

export default Login