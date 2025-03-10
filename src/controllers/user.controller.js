import { asyncHandler } from "../utils/asyncHandler.js"
import {ApiError} from "../utils/ApiError.js"
import {User} from "../models/user.model.js"
import {uploadOnCloudinary} from "../utils/cloudinary.js"
import {ApiResponse} from "../utils/ApiResponse.js"

const generateAccessAndRefreshTokens = async ({userId}) => {
      try {
        const user = await User.findById(userId)
        console.log('user: ',user)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        console.log(accessToken,refreshToken)
        user.refreshToken = refreshToken
        await user.save({validateBeforeSave: false})

        return {accessToken,refreshToken}
      } catch (error) {
        throw new ApiError(500,"Something went wrong while generating refresh and access token")
      }
}

const registerUser = asyncHandler( async (req , res ) => {
    //get details of user
    //validation - not empty 
    //check if user already exists : username
    //check for images , : avatar
    //upload them to cloudinary , avatar 
    // create user object - create entry in db
    // remove password and refresh token field from response
    //check for user creation
    //return res

    const {fullName , email ,username , password } = req.body
    console.log("email: ",email);

    if(
        [fullName,email,username,password].some((field) => field?.trim() === "")
    ) {
        throw new ApiError(400,"All fields are required")
    }

    const existedUser = await User.findOne({
        $or: [ {username} , {email}]
    })

    if(existedUser) {
        throw new ApiError(409,"User already exists")
    }

    const avatarLoccalPath = req.files?.avatar[0]?.path;
    //const coverLoccalPath = req.files?.coverImage[0]?.path;

    let coverLoccalPath;

    if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length >0 )
    {
        coverLoccalPath = req.files.coverImage[0].path
    }

    if(!avatarLoccalPath){
        throw new ApiError(400,"avatar is required")
    }

    const avatar = await uploadOnCloudinary(avatarLoccalPath)
    const coverImage = await uploadOnCloudinary(coverLoccalPath)

    if(!avatar){
        throw new ApiError(500,"avatar server error")
    }

    const user = await User.create({
        fullName,
        avatar : avatar.url,
        coverImage : coverImage?.url || "",
        email,
        password,
        username:username.toLowerCase()
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if (!createdUser) {
        throw new ApiError(500,"Something went wrong while registering")
    }

    return res.status(201).json(
        new ApiResponse(200,createdUser,"User registered Successfully")
    )
})

const loginUser = asyncHandler(async (req,res) => {
    // get data
    // find user
    //check password
    // generate access and refresh token 
    // send them via cookies
    // send a success message

    const {email , password , username} = req.body ;

    console.log('email: ' ,email)
    if(!username && !email) {
        throw new ApiError(400,"username or password required")
    }

    const user = await User.findOne({
        $or:[{username} , {email} ]
    })

    if(!user) {
        throw new ApiError(404,"User Not Found")
    }

    const isPasswordValid = await user.isPasswordCorrect(password)

    if(!isPasswordValid) {
        throw new ApiError(401,"Invalid user credentials")
    }

    const {accessToken,refreshToken} = await generateAccessAndRefreshTokens({userId:user._id})

    const loggedInuser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    const options = {
        httpOnly:true,
        secure:true
    }

    return res
    .status(200)
    .cookie("accessToken",accessToken,options)
    .cookie("refreshToken",refreshToken,options)
    .json(
        new ApiResponse(
            200,
            {
                user:loggedInuser,accessToken,
                refreshToken
            },
            "User logged In Successfully"
        )
    )
})

const logoutUser = asyncHandler(async(req,res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
           $set: {
                refreshToken:undefined
           }
        },
        {
            new:true
        }
    )

    const options = {
        httpOnly:true,
        secure:true
    }

    return res
        .status(200)
        .clearCookie("accessToken",options)
        .clearCookie("refreshToken",options)
        .json(new ApiResponse(200,"successfully loggedout"))
})

export {
    registerUser,
    loginUser,
    logoutUser
}