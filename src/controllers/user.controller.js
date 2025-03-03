import { asyncHandler } from "../utils/asyncHandler.js"
import {ApiError} from "../utils/ApiError.js"
import {User} from "../models/user.model.js"
import {uploadOnCloudinary} from "../utils/cloudinary.js"
import {ApiResponse} from "../utils/ApiResponse.js"

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

    const existedUser =  User.findOne({
        $or: [ {username} , {email}]
    })

    if(existedUser) {
        throw new ApiError(409,"User already exists")
    }

    const avatarLoccalPath = req.files?.avatar[0]?.path;
    const coverLoccalPath = req.files?.coverImage[0]?.path;

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

    if (createdUser) {
        throw new ApiError(500,"Something went wrong while registering")
    }

    return res.status(201).json(
        new ApiResponse(200,createdUser,"User registered Successfully")
    )
})

export {registerUser}